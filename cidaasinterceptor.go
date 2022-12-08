package cidaasinterceptor

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type ContextKey int

const TokenDataKey ContextKey = 3941119

type TokenData struct {
	Sub string
	Aud string
}

// Options passed to the Interceptor (Base URI, ClientID)
type Options struct {
	BaseURI  string
	ClientID string
	Debug    bool
}

// CidaasInterceptor to secure APIs based on OAuth 2.0
type CidaasInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
	jwks      Jwks
}

type introspectRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint"`
}
type introspectResponse struct {
	Iss    string   `json:"iss"`
	Active bool     `json:"active"`
	Aud    string   `json:"aud"`
	Sub    string   `json:"sub"`
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
}

type cidaasEndpoints struct {
	Issuer                              string `json:"issuer"`
	UserinfoEndpoint                    string `json:"userinfo_endpoint"`
	AuthorizationEndpoint               string `json:"authorization_endpoint"`
	IntrospectionEndpoint               string `json:"introspection_endpoint"`
	IntrospectionasyncupdateEndpoint    string `json:"introspection_async_update_endpoint"`
	RevocationEndpoint                  string `json:"revocation_endpoint"`
	TokenEndpoint                       string `json:"token_endpoint"`
	JwksURI                             string `json:"jwks_uri"`
	Checksessioniframe                  string `json:"check_session_iframe"`
	EndsessionEndpoint                  string `json:"end_session_endpoint"`
	SocialprovidertokenresolverEndpoint string `json:"social_provider_token_resolver_endpoint"`
	DeviceauthorizationEndpoint         string `json:"device_authorization_endpoint"`
}

// Jwks struct containing a list of keys to verify a signature of token
type Jwks struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey struct containing data of a key to verify a signature of token
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type cidaasTokenClaims struct {
	Roles  []string `json:"roles"`
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

// New returns a newly constructed cidaasInterceptor instance with the provided options
func New(opts Options) (*CidaasInterceptor, error) {
	if opts == (Options{}) || opts.BaseURI == "" {
		log.Printf("No options passed! BaseURI: %v", opts.BaseURI)
		return nil, errors.New("no Base URI passed")
	}
	log.Println("Initialization started")
	resp, err := http.Get(opts.BaseURI + "/.well-known/openid-configuration")

	// check if any error when retrieving the JWKS
	if err != nil {
		log.Printf("Well Known call failed! Error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Decode cidaas well-known to endpoints object
	var CidaasEndpoints = cidaasEndpoints{}
	err = json.NewDecoder(resp.Body).Decode(&CidaasEndpoints)
	if err != nil {
		return nil, err
	}

	keys, err := getKeys(opts.BaseURI)
	if err != nil {
		return nil, err
	}

	return &CidaasInterceptor{
		Options:   opts,
		endpoints: CidaasEndpoints,
		jwks:      keys,
	}, nil
}

// VerifyTokenBySignature (check for exp time and scopes and roles)
func (m *CidaasInterceptor) VerifyTokenBySignature(next http.Handler, scopes []string, roles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := getTokenFromAuthHeader(r)

		// Error in getting Token from AuthHeader
		if err != nil {
			log.Printf("Error getting token from Header: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse Token
		token, err := jwt.ParseWithClaims(tokenString, &cidaasTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate Signing Method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			pem, err := getKey(token, m.jwks)
			if err != nil {
				log.Printf("Reloading keys for Kid : %v", token.Header["kid"])
				keys, err := getKeys(m.Options.BaseURI)
				if err != nil {
					return nil, err
				}
				m.jwks = keys
				pem, err1 := getKey(token, m.jwks)
				if err1 == nil {
					return pem, nil
				}
				return nil, fmt.Errorf("no key found for: %v", token.Header["kid"])
			}
			return pem, nil
		})

		// Check if there was an error in parsing
		if err != nil {
			log.Printf("Error parsing token: %v", err)
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		sub := ""
		aud := ""

		if claims, ok := token.Claims.(*cidaasTokenClaims); ok && token.Valid {
			// Check for roles and scopes in token data
			if !CheckScopesAndRoles(claims.Scopes, claims.Roles, scopes, roles) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			// Verify issuer in token data based on baseURI given in options of interceptor
			if !claims.VerifyIssuer(m.Options.BaseURI, true) {
				log.Println("Issuer mismatch")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			// Verify exp times in token data based on current timestamp
			if !claims.VerifyExpiresAt(time.Now(), true) {
				log.Println("Token expired!")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if m.Options.ClientID != "" {
				if claims.Audience[0] != m.Options.ClientID {
					log.Println("Aud mismatch!")
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			sub = claims.Subject
			aud = claims.Audience[0]
		} else {
			log.Println("Issue with claims")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		rWithTokenData := r.WithContext(context.WithValue(r.Context(), TokenDataKey, TokenData{Sub: sub, Aud: aud}))
		next.ServeHTTP(w, rWithTokenData)
	})
}

// VerifyTokenByIntrospect (check for exp time, issuer and scopes and roles)
func (m *CidaasInterceptor) VerifyTokenByIntrospect(next http.Handler, scopes []string, roles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Token From Auth Header
		tokenString, err := getTokenFromAuthHeader(r)
		if err != nil {
			log.Printf("Error getting token from Header: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Marshal Token to introspectRequest and perform POST Call to Introspect Endpoint
		introspectReqBody, err := json.Marshal(introspectRequest{tokenString, "access_token"})
		if err != nil {
			log.Printf("Error mapping introspect request: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		resp, err := http.Post(m.endpoints.IntrospectionEndpoint, "application/json", bytes.NewBuffer(introspectReqBody))

		// If Introspect was not successful log error and return Unauthorized
		if err != nil {
			log.Printf("Error calling introspect: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		defer resp.Body.Close()

		// Map Introspect call response (decode)
		var introspectRespBody introspectResponse
		errDec := json.NewDecoder(resp.Body).Decode(&introspectRespBody)
		if errDec != nil {
			log.Printf("Error mapping introspect Response: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Println(introspectRespBody)
		// Check if token is active, if not return Unauthorized, root cause could be that token is expired or revoked
		if !introspectRespBody.Active {
			log.Printf("Token Expired/Revoked: Token.Active: %v", introspectRespBody.Active)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check for issuer in token data
		if introspectRespBody.Iss != m.Options.BaseURI {
			log.Println("Issuer mismatch")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Check for roles and scopes in token data
		if !CheckScopesAndRoles(introspectRespBody.Scopes, introspectRespBody.Roles, scopes, roles) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if m.Options.ClientID != "" {
			if introspectRespBody.Aud != m.Options.ClientID {
				log.Println("Aud mismatch!")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		rWithTokenData := r.WithContext(context.WithValue(r.Context(), TokenDataKey, TokenData{Sub: introspectRespBody.Sub, Aud: introspectRespBody.Aud}))
		next.ServeHTTP(w, rWithTokenData)
	})
}

// get the Token from The Auth Header
func getTokenFromAuthHeader(r *http.Request) (s string, err error) {
	authorizationHeader := r.Header.Get("Authorization")
	// check if Authorization token is set
	if authorizationHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	// Remove bearer in the authorization header
	authorizationHeaderParts := strings.Fields(authorizationHeader)
	if len(authorizationHeaderParts) != 2 || strings.ToLower(authorizationHeaderParts[0]) != "bearer" {
		return "", errors.New("invalid Token - not of type: Bearer")
	}
	return authorizationHeaderParts[1], nil
}

// CheckScopesAndRoles based on Introspect Response and requested scopes and roles
func CheckScopesAndRoles(tokenScopes []string, tokenRoles []string, scopes []string, roles []string) bool {
	if scopes != nil || len(scopes) > 0 {
		// Check for request scopes in token data
		if !Contains(tokenScopes, scopes) {
			log.Println("Scopes mismatch")
			return false
		}
	}
	if roles != nil || len(roles) > 0 {
		// Check for request roles in token data
		if !Contains(tokenRoles, roles) {
			log.Println("Roles mismatch")
			return false
		}
	}
	return true
}

// Contains Call checking if scopes/roles in the tokendata
func Contains(tokenData []string, RequestedData []string) bool {
	for _, r := range RequestedData {
		for i, t := range tokenData {
			if t == r {
				break
			}
			if i+1 == len(tokenData) {
				log.Println("RequestedData: " + r + " not in Token")
				return false
			}
		}
	}
	return true
}

// getKey based on kid in token and check in jwks
func getKey(token *jwt.Token, jwks Jwks) (*rsa.PublicKey, error) {

	// loop over jwks array and find key for kid of the token header
	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			pub, err := extractPublicKeyFromJWK(jwks.Keys[k])
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
	}

	err := errors.New("unable to find appropriate key")
	return nil, err

}

// getKeys call the JWKS endpoint
func getKeys(baseURI string) (Jwks, error) {

	// Call JWKS endpoint
	var jwks = Jwks{}
	resp, err := http.Get(baseURI + "/.well-known/jwks.json")

	// check if any error when retrieving the JWKS
	if err != nil {
		return jwks, err
	}
	defer resp.Body.Close()

	// Decode JWKS to JWKS[] type
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	if err != nil {
		return jwks, err
	}
	return jwks, nil
}

func extractPublicKeyFromJWK(jwk JSONWebKey) (publicKey *rsa.PublicKey, err error) {
	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Base64 decoding failed")
	}
	e := 0
	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Fatal("need to decode e:", jwk.E)
		return nil, errors.New("e is not the expected default")
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}
	return pk, nil
}

// TODO Async Introspect
