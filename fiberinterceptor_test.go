package cidaasinterceptor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestNewFiberInterceptor_Error(t *testing.T) {
	interceptor, err := NewFiberInterceptor(Options{})
	assert.Error(t, err)
	assert.Nil(t, interceptor)
}

func TestNewFiberInterceptor_Success(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
}

func TestFiberInterceptor_VerifyTokenBySignature_NoToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)

	res := doFiberRequest(t, "", interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestFiberInterceptor_VerifyTokenBySignature_InvalidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, nil, uri, false)
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
	res := doFiberRequest(t, token, interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestFiberInterceptor_VerifyTokenBySignature_Success(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, pk, uri, false)
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri})
	assert.NoError(t, err)
	res := doFiberRequest(t, token, interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, res.StatusCode, "handler should return 200 status code")
}

func TestFiberInterceptor_VerifyTokenBySignature_SuccessAfterKeyNotFound(t *testing.T) {
	calls := 0
	jwks, pk := createJwksKeys(t, nil)
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cidaasEndpoints{
			JwksURI: fmt.Sprintf("%v/.well-known/jwks.json", mockServer.URL),
		})
	})
	mockHandler.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			json.NewEncoder(w).Encode(jwks)
			return
		}
		jwks.Keys[0].Kid = "newKey"
		fmt.Println(jwks)
		json.NewEncoder(w).Encode(jwks)
	})
	mockServer = httptest.NewServer(mockHandler)
	defer mockServer.Close()
	token := createToken(t, pk, mockServer.URL, false, "newKey")
	interceptor, err := NewFiberInterceptor(Options{BaseURI: mockServer.URL})
	assert.NoError(t, err)
	var tokenData TokenData
	// first call
	res := doFiberRequest(t, token, interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, res.StatusCode, "handler should return 200 status code")
	// second call ensures that the cache of the keys has been updated correctly
	res = doFiberRequest(t, token, interceptor.VerifyTokenBySignature(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, res.StatusCode, "handler should return 200 status code")
	assert.Equal(t, 2, calls)
}

func TestFiberInterceptor_VerifyTokenByIntrospect_NoToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	res := doFiberRequest(t, "", interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestFiberInterceptor_VerifyTokenByIntrospect_InvalidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, nil, uri, false)
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: false})
	defer closeIntrospectSrv()
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}
	res := doFiberRequest(t, token, interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestFiberInterceptor_VerifyTokenByIntrospect_Success(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, pk, uri, false)
	interceptor, err := NewFiberInterceptor(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: true, Iss: uri})
	defer closeIntrospectSrv()
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}
	res := doFiberRequest(t, token, interceptor.VerifyTokenByIntrospect(SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	var tokenData TokenData
	json.NewDecoder(res.Body).Decode(&tokenData)
	assert.Equal(t, http.StatusOK, res.StatusCode, "handler should return 200 status code")
}

func doFiberRequest(t *testing.T, token string, interceptorHandler func(*fiber.Ctx) error) *http.Response {
	app := fiber.New()
	app.Get("/check", interceptorHandler, checkHandler)
	req, err := http.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", token))
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.Test(req, 60*1000)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err, "expected no error while calling endpoint")
	return res
}

func checkHandler(ctx *fiber.Ctx) error {
	token := ctx.Locals(FiberTokenDataKey)
	tokenData := token.(TokenData)
	_ = ctx.Status(fiber.StatusOK).JSON(tokenData)
	return nil
}
