package cidaasinterceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifySignature_InvalidSignature(t *testing.T) {
	jwks, _ := createJwksKeys(t, nil)
	token := createToken(t, nil, "", false)
	tokenData := verifySignature(Options{Debug: true}, cidaasEndpoints{}, &jwks, token, SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_KeyNotFound(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createToken(t, pk, "", false, "newKey")
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_KeyAfterReloadFound(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(cidaasEndpoints{
			JwksURI: fmt.Sprintf("%v/.well-known/jwks.json", mockServer.URL),
		})
	})
	mockHandler.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks.Keys[0].Kid = "newKey"
		fmt.Println(jwks)
		json.NewEncoder(w).Encode(jwks)
	})
	mockServer = httptest.NewServer(mockHandler)
	defer mockServer.Close()
	jwksURI := fmt.Sprintf("%v/.well-known/jwks.json", mockServer.URL)
	token := createToken(t, pk, "", false, "newKey")
	tokenData := verifySignature(Options{BaseURI: mockServer.URL, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_Expired(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createToken(t, pk, uri, true)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"profile"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_IssuerMismatch(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createToken(t, pk, "", false)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"profile"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_ScopeMismatch(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createToken(t, pk, uri, false)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"mismatch"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_NoScopeInToken(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesAndRoles(t, pk, uri, false, nil, nil)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"scope"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_RoleMismatch(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesAndRoles(t, pk, uri, false, nil, []string{"otherrole"})
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Roles: []string{"role"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_NoRoleInToken(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesAndRoles(t, pk, uri, false, nil, nil)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Roles: []string{"role"}})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_AllowAnonymousSub_Valid(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesRolesSub(t, pk, uri, false, nil, nil, anonymousSub)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Roles: []string{"role"}, AllowAnonymousSub: true})
	assert.NotNil(t, tokenData)
}

func TestVerifySignature_AllowAnonymousSub_InValidScope(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesRolesSub(t, pk, uri, false, []string{"scope1"}, nil, anonymousSub)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"scope2"}, Roles: []string{"role"}, AllowAnonymousSub: true})
	assert.Nil(t, tokenData)
}

func TestVerifySignature_Success(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createToken(t, pk, uri, false)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"profile"}})
	assert.NotNil(t, tokenData)
	assert.Equal(t, "clientTest", tokenData.Aud)
	assert.Equal(t, "sub", tokenData.Sub)
}

func TestVerifySignature_SecondScopeMatch(t *testing.T) {
	jwks, pk := createJwksKeys(t, nil)
	uri, jwksURI, close := createWellKnownMockServer(jwks)
	token := createTokenWithScopesAndRoles(t, pk, uri, false, []string{"scope2"}, nil)
	defer close()
	tokenData := verifySignature(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{JwksURI: jwksURI}, &jwks, token, SecurityOptions{Scopes: []string{"scope1", "scope2"}})
	assert.NotNil(t, tokenData)
}

func createJwksKeys(t *testing.T, pk *rsa.PrivateKey) (Jwks, *rsa.PrivateKey) {
	if pk == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pk = key
	}
	n := base64.RawURLEncoding.EncodeToString(pk.N.Bytes())
	kid := "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	key1 := JSONWebKey{N: n, E: "AQAB", Alg: "RS256", Use: "sig", Kid: kid, Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	return Jwks{Keys: []JSONWebKey{key1, key2}}, pk
}

func createWellKnownMockServer(jwks Jwks, noURI ...bool) (string, string, func()) {
	var mockServer *httptest.Server
	// create server for the well known calls
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if len(noURI) > 0 {
			json.NewEncoder(w).Encode(cidaasEndpoints{})
			return
		}
		json.NewEncoder(w).Encode(cidaasEndpoints{
			JwksURI: fmt.Sprintf("%v/.well-known/jwks.json", mockServer.URL),
		})
	})
	mockHandler.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	})
	mockServer = httptest.NewServer(mockHandler)
	jwksURI := fmt.Sprintf("%v/.well-known/jwks.json", mockServer.URL)
	return mockServer.URL, jwksURI, func() { mockServer.Close() }
}
