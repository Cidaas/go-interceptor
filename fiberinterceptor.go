package cidaasinterceptor

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// FiberTokenDataKey key to access the token data ofthe request context
const FiberTokenDataKey = "tokendata"

// FiberInterceptor to secure APIs based on OAuth 2.0 with fiber
type FiberInterceptor struct {
	Options   Options
	endpoints cidaasEndpoints
	jwks      *Jwks
}

// NewFiberInterceptor returns a newly constructed cidaasInterceptor instance with the provided options
func NewFiberInterceptor(opts Options) (*FiberInterceptor, error) {
	cidaasEndpoints, keys, err := newInterceptor(opts)
	if err != nil {
		return nil, err
	}
	return &FiberInterceptor{
		Options:   opts,
		endpoints: cidaasEndpoints,
		jwks:      &keys,
	}, nil
}

// VerifyTokenBySignature (check for exp time and scopes and roles)
func (m *FiberInterceptor) VerifyTokenBySignature(apiOptions SecurityOptions) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		tokenString := getToken(ctx.Request())
		if tokenString == "" { // error getting Token from auth header
			log.Printf("Error getting token from Header")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		tokenData := verifySignature(m.Options, m.endpoints, m.jwks, tokenString, apiOptions)
		if tokenData == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("Invalid token")
		}
		ctx.Locals(FiberTokenDataKey, *tokenData)
		return ctx.Next()
	}
}

// VerifyTokenByIntrospect (check for exp time, issuer and scopes and roles)
func (m *FiberInterceptor) VerifyTokenByIntrospect(apiOptions SecurityOptions) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// get token from auth header
		tokenString := getToken(ctx.Request())
		if tokenString == "" { // error getting Token from auth header
			log.Printf("Error getting token from Header")
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		tokenData := introspectToken(m.Options, m.endpoints, tokenString, apiOptions)
		if tokenData == nil {
			return ctx.Status(fiber.StatusUnauthorized).SendString("Unauthorized")
		}
		ctx.Locals(FiberTokenDataKey, *tokenData)
		return ctx.Next()
	}
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
