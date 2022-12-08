package cidaasinterceptor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/valyala/fasthttp"
)

type FiberInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
	jwks      Jwks
}

const FiberTokenDataKey = "tokendata"

// NewFiberInterceptor returns a newly constructed cidaasInterceptor instance with the provided options
func NewFiberInterceptor(opts Options) (*FiberInterceptor, error) {
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

	return &FiberInterceptor{
		Options:   opts,
		endpoints: CidaasEndpoints,
		jwks:      keys,
	}, nil
}

// VerifyTokenBySignature (check for exp time and scopes and roles)
func (m *FiberInterceptor) VerifyTokenBySignature(scopes []string, roles []string) fiber.Handler {
	return fiber.Handler(func(ctx *fiber.Ctx) error {
		tokenString := getToken(ctx.Request())

		// Error in getting Token from AuthHeader
		if tokenString == "" {
			log.Printf("Error getting token from Header")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
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
			return ctx.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}
		sub := ""
		aud := ""

		if claims, ok := token.Claims.(*cidaasTokenClaims); ok && token.Valid {
			// Check for roles and scopes in token data
			if m.Options.Debug {
				log.Printf("Scopes: %v", claims.Scopes)
				log.Printf("Roles: %v", claims.Roles)
			}
			if !CheckScopesAndRoles(claims.Scopes, claims.Roles, scopes, roles) {
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			// Verify issuer in token data based on baseURI given in options of interceptor
			if !claims.VerifyIssuer(m.Options.BaseURI, true) {
				log.Printf("Issuer mismatch, issuer: %v, base URI: %v", claims.Issuer, m.Options.BaseURI)
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			// Verify exp times in token data based on current timestamp
			if !claims.VerifyExpiresAt(time.Now(), true) {
				log.Printf("Token expired!, expiration: %v, now: %v", claims.ExpiresAt, time.Now())
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			if m.Options.ClientID != "" {
				if claims.Audience[0] != m.Options.ClientID {
					log.Printf("Aud mismatch!, aud: %v, clientID: %v", claims.Audience[0], m.Options.ClientID)
					return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
				}
			}
			sub = claims.Subject
			aud = claims.Audience[0]
		} else {
			log.Println("Issue without claims")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		ctx.Locals(FiberTokenDataKey, TokenData{Aud: aud, Sub: sub})
		return ctx.Next()
	})
}

// VerifyTokenByIntrospect (check for exp time, issuer and scopes and roles)
func (m *FiberInterceptor) VerifyTokenByIntrospect(scopes []string, roles []string) fiber.Handler {
	return fiber.Handler(func(ctx *fiber.Ctx) error {
		// Get Token From Auth Header
		tokenString := getToken(ctx.Request())

		// Error in getting Token from AuthHeader
		if tokenString == "" {
			log.Printf("Error getting token from Header")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}

		// Marshal Token to introspectRequest and perform POST Call to Introspect Endpoint
		introspectReqBody, err := json.Marshal(introspectRequest{tokenString, "access_token"})
		if err != nil {
			log.Printf("Error mapping introspect request: %v", err)
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		if m.Options.Debug {
			log.Printf("IntrospectReqBody: %v", introspectReqBody)
		}

		resp, err := http.Post(m.endpoints.IntrospectionEndpoint, "application/json", bytes.NewBuffer(introspectReqBody))

		// If Introspect was not successful log error and return Unauthorized
		if err != nil {
			log.Printf("Error calling introspect: %v", err)
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		defer resp.Body.Close()

		var introspectRespBody introspectResponse
		errDec := json.NewDecoder(resp.Body).Decode(&introspectRespBody)
		if errDec != nil {
			log.Printf("Error mapping introspect Response: %v", err)
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}

		if m.Options.Debug {
			log.Printf("IntrospectRespBody: %v", introspectRespBody)
		}

		if !introspectRespBody.Active {
			log.Printf("Token Expired/Revoked: Token.Active: %v", introspectRespBody.Active)
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}

		// Check for issuer in token data
		if introspectRespBody.Iss != m.Options.BaseURI {
			log.Printf("Issuer mismatch, issuer: %v, base URI: %v", introspectRespBody.Iss, m.Options.BaseURI)
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}

		// Check for roles and scopes in token data
		if !CheckScopesAndRoles(introspectRespBody.Scopes, introspectRespBody.Roles, scopes, roles) {
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}

		if m.Options.ClientID != "" {
			if introspectRespBody.Aud != m.Options.ClientID {
				log.Println("Aud mismatch!")
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
		}
		ctx.Locals(FiberTokenDataKey, TokenData{Sub: introspectRespBody.Sub, Aud: introspectRespBody.Aud})
		return ctx.Next()
	})
}

func getHeaderString(key string, r *fasthttp.Request) string {
	return string(r.Header.Peek(key))
}

func getToken(r *fasthttp.Request) string {
	header := getHeaderString("Authorization", r)
	if header != "" {
		parts := strings.Split(header, " ")
		if len(parts) == 2 {
			return parts[1]
		}
	}
	header = getHeaderString("access_token", r)
	return header
}
