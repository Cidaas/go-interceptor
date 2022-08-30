package cidaasinterceptor

import (
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

// New returns a newly constructed cidaasInterceptor instance with the provided options
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
			log.Printf("Scopes: %v", claims.Scopes)
			log.Printf("Roles: %v", claims.Roles)
			if !CheckScopesAndRoles(claims.Scopes, claims.Roles, scopes, roles) {
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			// Verify issuer in token data based on baseURI given in options of interceptor
			if !claims.VerifyIssuer(m.Options.BaseURI, true) {
				log.Println("Issuer mismatch")
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			//Verify exp times in token data based on current timestamp
			if !claims.VerifyExpiresAt(time.Now(), true) {
				log.Println("Token expired!")
				return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
			}
			if m.Options.ClientID != "" {
				if claims.Audience[0] != m.Options.ClientID {
					log.Println("Aud mismatch!")
					return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
				}
			}
			sub = claims.Subject
			aud = claims.Audience[0]
		} else {
			log.Println("Issue with claims")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		ctx.Locals(FiberTokenDataKey, TokenData{Aud: aud, Sub: sub})
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
