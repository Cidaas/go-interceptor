package cidaasinterceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func TestFiberInterceptor_VerifyTokenBySignature(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	registeredClaims := jwt.RegisteredClaims{
		Issuer:    "https://base.cidaas.de",
		Subject:   "ANONYMOUS",
		Audience:  jwt.ClaimStrings{"clientTest"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1000 * time.Second)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        "7da05fac-0f79-4925-bb58-ab9602cb581f",
	}
	token.Claims = cidaasTokenClaims{Scopes: []string{"profile", "cidaas:compromissed_credentials"}, RegisteredClaims: registeredClaims}
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := token.SignedString(rsakey)
	key1 := JSONWebKey{N: base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes()), E: "AQAB", Alg: "RS256", Use: "sig", Kid: "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}

	cidaasInterceptor := FiberInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "clientTest"}, cidaasEndpoints{}, jwks}
	app := fiber.New()
	app.Get("/check", cidaasInterceptor.VerifyTokenBySignature([]string{"profile", "cidaas:compromissed_credentials"}, nil), checkHandler)

	req, err := http.NewRequest("GET", "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", s))
	if err != nil {
		t.Fatal(err)
	}

	res, err := app.Test(req, 60*1000)
	assert.Nil(t, err, "expected no error while calling endpoint")
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "ANONYMOUS", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, fiber.StatusOK, res.StatusCode, "handler should return 200 status code")
}

func TestFiberInterceptor_VerifyTokenByIntrospect(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	registeredClaims := jwt.RegisteredClaims{
		Issuer:    "https://base.cidaas.de",
		Subject:   "ANONYMOUS",
		Audience:  jwt.ClaimStrings{"clientTest"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1000 * time.Second)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        "7da05fac-0f79-4925-bb58-ab9602cb581f",
	}
	token.Claims = cidaasTokenClaims{Scopes: []string{"profile", "cidaas:compromissed_credentials"}, RegisteredClaims: registeredClaims}
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := token.SignedString(rsakey)
	key1 := JSONWebKey{N: base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes()), E: "AQAB", Alg: "RS256", Use: "sig", Kid: "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}

	cidaasInterceptor := FiberInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "clientTest"}, cidaasEndpoints{}, jwks}
	app := fiber.New()
	app.Get("/check", cidaasInterceptor.VerifyTokenByIntrospect([]string{"profile", "cidaas:compromissed_credentials"}, nil), checkHandler)

	req, err := http.NewRequest("GET", "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", s))
	if err != nil {
		t.Fatal(err)
	}

	res, err := app.Test(req, 60*1000)
	assert.Nil(t, err, "expected no error while calling endpoint")
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, fiber.StatusUnauthorized, res.StatusCode, "handler should return 200 status code")
}

func checkHandler(ctx *fiber.Ctx) error {
	token := ctx.Locals(FiberTokenDataKey)
	tokenData := token.(TokenData)
	_ = ctx.Status(fiber.StatusOK).JSON(tokenData)
	return nil
}
