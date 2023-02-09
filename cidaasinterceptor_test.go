package cidaasinterceptor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewHttpInterceptor_Error(t *testing.T) {
	interceptor, err := New(Options{})
	assert.Error(t, err)
	assert.Nil(t, interceptor)
}

func TestNewHttpInterceptor_Success(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := New(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
}

func TestHttpInterceptor_SignatureHandler_NoToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := New(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
	rr := doHTTPRequest(t, "", interceptor.VerifyTokenBySignature(http.HandlerFunc(healthCheckHandler), SecurityOptions{}))
	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)
}

func TestHttpInterceptor_SignatureHandler_InvalidSignature(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, nil, uri, false)
	interceptor, err := New(Options{BaseURI: uri})
	assert.NoError(t, err)
	assert.NotNil(t, interceptor)
	rr := doHTTPRequest(t, token, interceptor.VerifyTokenBySignature(http.HandlerFunc(healthCheckHandler), SecurityOptions{}))
	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)
}

func TestHttpInterceptor_SignatureHandler_Success(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, pk, uri, false)
	interceptor, err := New(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)

	rr := doHTTPRequest(t, token, interceptor.VerifyTokenBySignature(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	var tokenData TokenData
	json.NewDecoder(rr.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, rr.Code, "handler should return 200 status code")
}

func TestHttpInterceptor_SignatureHandler_SuccessAfterKeyNotFound(t *testing.T) {
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
	interceptor, err := New(Options{BaseURI: mockServer.URL, Debug: true})
	assert.NoError(t, err)
	var tokenData TokenData
	// first call
	rr := doHTTPRequest(t, token, interceptor.VerifyTokenBySignature(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	json.NewDecoder(rr.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, rr.Code, "handler should return 200 status code")
	// second call ensures that the cache of the keys has been updated correctly
	rr = doHTTPRequest(t, token, interceptor.VerifyTokenBySignature(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	json.NewDecoder(rr.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, rr.Code, "handler should return 200 status code")
	assert.Equal(t, 2, calls)
}

func TestHttpInterceptor_IntrospectHandler_NoToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	interceptor, err := New(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: true, Iss: uri})
	defer closeIntrospectSrv()
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}
	rr := doHTTPRequest(t, "", interceptor.VerifyTokenByIntrospect(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)
}

func TestHttpInterceptor_IntrospectHandler_InvalidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, nil, uri, false)
	interceptor, err := New(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: false})
	defer closeIntrospectSrv()
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}
	rr := doHTTPRequest(t, token, interceptor.VerifyTokenByIntrospect(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)
}

func TestHttpInterceptor_IntrospectHandler_ValidToken(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	uri, _, close := createWellKnownMockServer(jwks)
	defer close()
	token := createToken(t, nil, uri, false)
	interceptor, err := New(Options{BaseURI: uri, Debug: true})
	assert.NoError(t, err)
	introspectURI, closeIntrospectSrv := createIntrospectMockServer(introspectResponse{Active: true, Iss: uri, Aud: "clientTest", Sub: "sub"})
	defer closeIntrospectSrv()
	interceptor.endpoints = cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", introspectURI)}
	rr := doHTTPRequest(t, token, interceptor.VerifyTokenByIntrospect(http.HandlerFunc(healthCheckHandler), SecurityOptions{Scopes: []string{"profile", "cidaas:compromissed_credentials"}}))
	assert.Equal(t, http.StatusOK, rr.Result().StatusCode)
	var tokenData TokenData
	json.NewDecoder(rr.Body).Decode(&tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud, "Aud in tokenData should be passed as context in request and be equal")
	assert.Equal(t, "sub", tokenData.Sub, "Sub in tokenData should be passed as context in request and be equal")
	assert.Equal(t, http.StatusOK, rr.Code, "handler should return 200 status code")
}

func TestSuccess_getTokenFromAuthHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Add("Authorization", "bearer token")
	header, err := getTokenFromAuthHeader(req)
	assert.Nil(t, err)
	assert.Equal(t, "token", header, "Authorization header should be found and be well-formed")
}

func TestFailure_getTokenFromAuthHeader_NoHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	header, err := getTokenFromAuthHeader(req)
	assert.NotNil(t, err)
	assert.Equal(t, "", header, "Authorization header should be there")
	assert.Equal(t, "missing Authorization header", err.Error(), "Authorization header should be missing")
}

func TestFailure_getTokenFromAuthHeader_WrongHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Add("Authorization", "token")
	header, err := getTokenFromAuthHeader(req)
	assert.NotNil(t, err)
	assert.Equal(t, "", header, "Authorization header should be there")
	assert.Equal(t, "invalid Token - not of type: Bearer", err.Error(), "Authorization header should be malformed")
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	tokenData := r.Context().Value(TokenDataKey).(TokenData)
	w.WriteHeader(http.StatusOK)
	jsonData, _ := json.Marshal(tokenData)
	w.Write(jsonData)
}

func doHTTPRequest(t *testing.T, token string, interceptorHandler http.Handler) *httptest.ResponseRecorder {
	req, err := http.NewRequest("GET", "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", token))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	interceptorHandler.ServeHTTP(rr, req)
	return rr
}
