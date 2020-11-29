package gointerceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/stretchr/testify/assert"
)

// TestSuccess_CheckScopesAndRoles tests that scopes and roles validation works properly
func TestSuccess_CheckScopesAndRoles_ScopesAndRolesInToken(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	tokenRoles := []string{"USER", "DEVELOPER"}
	Scopes := []string{"profile", "email"}
	Roles := []string{"USER", "DEVELOPER"}
	assert.True(t, CheckScopesAndRoles(tokenScopes, tokenRoles, Scopes, Roles), "roles and scopes should match")
}

// TestSuccess_CheckScopesAndRoles tests that scopes and roles validation works properly - more scopes and roles in token
func TestSuccess_CheckScopesAndRoles_AdditionalScopesAndRoles(t *testing.T) {
	tokenScopes := []string{"profile", "email", "mobile"}
	tokenRoles := []string{"USER", "DEVELOPER", "MAINTAINER"}
	Scopes := []string{"profile", "email"}
	Roles := []string{"USER", "DEVELOPER"}
	assert.True(t, CheckScopesAndRoles(tokenScopes, tokenRoles, Scopes, Roles), "roles and scopes should match")
}

// TestSuccess_CheckScopes tests that scopes validation works properly
func TestSuccess_CheckScopes_ScopesInToken(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	Scopes := []string{"profile", "email"}
	assert.True(t, CheckScopesAndRoles(tokenScopes, nil, Scopes, nil), "scopes should match")
}

// TestSuccess_CheckRoles tests that roles validation works properly
func TestSuccess_CheckRoles_RolesInToken(t *testing.T) {
	tokenRoles := []string{"USER", "DEVELOPER"}
	Roles := []string{"USER", "DEVELOPER"}
	assert.True(t, CheckScopesAndRoles(nil, tokenRoles, nil, Roles), "roles should match")
}

// TestFailure_CheckScopesAndRoles tests that scopes and roles validation works properly - missing scopes in token
func TestFailure_CheckScopesAndRoles_MissingScopesInToken(t *testing.T) {
	tokenScopes := []string{"profile"}
	tokenRoles := []string{"USER", "DEVELOPER"}
	Scopes := []string{"profile", "email"}
	Roles := []string{"USER", "DEVELOPER"}
	assert.False(t, CheckScopesAndRoles(tokenScopes, tokenRoles, Scopes, Roles), "scopes should not match")
}

// TestFailure_CheckScopesAndRoles tests that scopes and roles validation works properly - missing roles in token
func TestFailure_CheckScopesAndRoles_MissingRolesInToken(t *testing.T) {
	tokenScopes := []string{"profile", "email"}
	tokenRoles := []string{"USER"}
	Scopes := []string{"profile", "email"}
	Roles := []string{"USER", "DEVELOPER"}
	assert.False(t, CheckScopesAndRoles(tokenScopes, tokenRoles, Scopes, Roles), "roles should not match")
}

// TestSuccess_getTokenFromAuthHeader tests that the Authorization header can be extracted from the request successfully
func TestSuccess_getTokenFromAuthHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Add("Authorization", "bearer token")
	header, err := getTokenFromAuthHeader(req)
	assert.Nil(t, err)
	assert.Equal(t, "token", header, "Authorization header should be found and be well-formed")
}

// TestFailure_getTokenFromAuthHeader_NoHeader tests that if no Authorization header is there an error is returned - Missing Authorization Header
func TestFailure_getTokenFromAuthHeader_NoHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	header, err := getTokenFromAuthHeader(req)
	assert.NotNil(t, err)
	assert.Equal(t, "", header, "Authorization header should be there")
	assert.Equal(t, "Missing Authorization header", err.Error(), "Authorization header should be missing")
}

// TestFailure_getTokenFromAuthHeader_WrongHeader tests that if no Authorization header is there an error is returned - Authorization Header / Token not of type bearer
func TestFailure_getTokenFromAuthHeader_WrongHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Add("Authorization", "token")
	header, err := getTokenFromAuthHeader(req)
	assert.NotNil(t, err)
	assert.Equal(t, "", header, "Authorization header should be there")
	assert.Equal(t, "Invalid Token - not of type: Bearer", err.Error(), "Authorization header should be malformed")
}

// TestSuccess_getKey tests that a key from a jwks can be selected successfully based on kid
func TestSuccess_getKey(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "kidtest"
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	key1 := JSONWebKey{N: base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes()), E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}
	cert, err := getKey(token, jwks)
	assert.Nil(t, err)
	assert.Equal(t, rsakey.PublicKey.E, cert.E, "E should match")
	assert.Equal(t, rsakey.PublicKey.N, cert.N, "N should match")
}

// TestFailure_getKey tests that a proper error is returned when no kid is in the jwks
func TestFailure_getKey(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "kidtest"
	key1 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest1", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}
	cert, err := getKey(token, jwks)
	assert.NotNil(t, err)
	assert.Nil(t, cert, "Cert/Key should be a empty string")
	assert.Equal(t, "Unable to find appropriate key", err.Error(), "error should be - Unable to find appropriate key")
}

// TestIntrospectHandlerFailure_NoToken tests that a 401 status code is returned when no token is passed
func TestIntrospectHandlerFailure_NoToken(t *testing.T) {
	getHandler := http.HandlerFunc(healthCheckHandler)
	req, err := http.NewRequest("GET", "/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	cidaasInterceptor := CidaasInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "testClient", ClientSecret: "testSecret"}, cidaasEndpoints{}, Jwks{}}
	handler := http.Handler(cidaasInterceptor.VerifyTokenByIntrospect(getHandler, []string{"profile", "cidaas:compromissed_credentials"}, nil))
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "handler should return 200 status code")
}

// TestSignatureHandlerFailure_NoToken tests that a 401 status code is returned when no token is passed
func TestSignatureHandlerFailure_NoToken(t *testing.T) {
	getHandler := http.HandlerFunc(healthCheckHandler)
	req, err := http.NewRequest("GET", "/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	cidaasInterceptor := CidaasInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "testClient", ClientSecret: "testSecret"}, cidaasEndpoints{}, Jwks{}}
	handler := http.Handler(cidaasInterceptor.VerifyTokenBySignature(getHandler, []string{"profile", "cidaas:compromissed_credentials"}, nil))
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "handler should return 200 status code")
}

// TestSignatureHandlerFailure_WrongSignature tests that a 401 status code is returned when a token has a invalid signature
func TestSignatureHandlerFailure_InvalidSignature(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	standardClaims := jwt.StandardClaims{Audience: "clientTest", ExpiresAt: time.Now().Unix() + 1000, Issuer: "https://base.cidaas.de", Id: "7da05fac-0f79-4925-bb58-ab9602cb581f", Subject: "ANONYMOUS", IssuedAt: time.Now().Unix()}
	token.Claims = cidaasTokenClaims{Scopes: []string{"profile", "cidaas:compromissed_credentials"}, StandardClaims: standardClaims}
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := token.SignedString(rsakey)
	_, err := ExportRsaPublicKeyAsPemStr(&rsakey.PublicKey)
	log.Printf("Error: %v", err)
	key1 := JSONWebKey{N: "31c8lXRnJEWvUkSdCDj0wRnIqCd1_XNmzoVYMdSlMr4Xy65_3YYl4LkFLKb6oMo-uY-v2s4sVfFyxPfgexMPEzlbggGBo2t47I4Mcsb1QO-pJvstQSKiX3Z2umNHIDD78gG1fegvimIeyAnbVLB306MCHcFFqh3Io_9DD7VDdo0", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}

	getHandler := http.HandlerFunc(healthCheckHandler)
	req, err := http.NewRequest("GET", "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", s))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	cidaasInterceptor := CidaasInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "testClient", ClientSecret: "testSecret"}, cidaasEndpoints{}, jwks}
	handler := http.Handler(cidaasInterceptor.VerifyTokenBySignature(getHandler, []string{"profile", "cidaas:compromissed_credentials"}, nil))
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "handler should return 200 status code")
}

// TestSignatureHandlerSuccess tests that a 200 status code is returned when a valid token is passed
func TestSignatureHandlerSuccess(t *testing.T) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536"
	standardClaims := jwt.StandardClaims{Audience: "clientTest", ExpiresAt: time.Now().Unix() + 1000, Issuer: "https://base.cidaas.de", Id: "7da05fac-0f79-4925-bb58-ab9602cb581f", Subject: "ANONYMOUS", IssuedAt: time.Now().Unix()}
	token.Claims = cidaasTokenClaims{Scopes: []string{"profile", "cidaas:compromissed_credentials"}, StandardClaims: standardClaims}
	rsakey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := token.SignedString(rsakey)
	key1 := JSONWebKey{N: base64.RawURLEncoding.EncodeToString(rsakey.N.Bytes()), E: "AQAB", Alg: "RS256", Use: "sig", Kid: "a6ef4de0-9a6f-4604-8fc5-f26f86b3a536", Kty: "RSA"}
	key2 := JSONWebKey{N: "ntest", E: "AQAB", Alg: "RS256", Use: "sig", Kid: "kidtest2", Kty: "RSA"}
	jwks := Jwks{[]JSONWebKey{key1, key2}}

	getHandler := http.HandlerFunc(healthCheckHandler)
	req, err := http.NewRequest("GET", "/check", nil)
	req.Header.Set("Authorization", fmt.Sprintf("bearer %v", s))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	cidaasInterceptor := CidaasInterceptor{Options{BaseURI: "https://base.cidaas.de", ClientID: "testClient", ClientSecret: "testSecret"}, cidaasEndpoints{}, jwks}
	handler := http.Handler(cidaasInterceptor.VerifyTokenBySignature(getHandler, []string{"profile", "cidaas:compromissed_credentials"}, nil))
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "handler should return 200 status code")
}

// healthCheckHandler will return an empty 200 OK response
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeypem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeybytes,
		},
	)

	return string(pubkeypem), nil
}
