package cidaasinterceptor

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
)

// ContextKey used to add request context
type ContextKey int

// TokenDataKey used to add the token data to the request context
const TokenDataKey ContextKey = 3941119

// CidaasInterceptor to secure APIs based on OAuth 2.0 for the net/http based api requests
type CidaasInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
	jwks      Jwks
}

// New returns a newly constructed cidaasInterceptor instance with the provided options
func New(opts Options) (*CidaasInterceptor, error) {
	cidaasEndpoints, keys, err := newInterceptor(opts)
	if err != nil {
		return nil, err
	}
	return &CidaasInterceptor{
		Options:   opts,
		endpoints: cidaasEndpoints,
		jwks:      keys,
	}, nil
}

// VerifyTokenBySignature (check for exp time and scopes and roles, no groups)
func (m *CidaasInterceptor) VerifyTokenBySignature(next http.Handler, apiOptions SecurityOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := getTokenFromAuthHeader(r)
		if err != nil { // error getting token from auth header
			log.Printf("Error getting token from Header: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenData := verifySignature(m.Options, m.endpoints, &m.jwks, tokenString, apiOptions)
		if tokenData == nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		rWithTokenData := r.WithContext(context.WithValue(r.Context(), TokenDataKey, *tokenData))
		next.ServeHTTP(w, rWithTokenData)
	})
}

// VerifyTokenByIntrospect (check for exp time, issuer and scopes, roles and groups)
func (m *CidaasInterceptor) VerifyTokenByIntrospect(next http.Handler, apiOptions SecurityOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get token from auth header
		tokenString, err := getTokenFromAuthHeader(r)
		if err != nil { // error getting Token from auth header
			log.Printf("Error getting token from Header: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenData := introspectToken(m.Options, m.endpoints, tokenString, apiOptions)
		if tokenData == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		rWithTokenData := r.WithContext(context.WithValue(r.Context(), TokenDataKey, *tokenData))
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
