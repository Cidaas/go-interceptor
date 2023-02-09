package cidaasinterceptor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntrospect_IntrospectCallError(t *testing.T) {
	tokenData := introspectToken(Options{BaseURI: "", Debug: true}, cidaasEndpoints{}, "", SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestIntrospect_NotActive(t *testing.T) {
	uri, close := createIntrospectMockServer(introspectResponse{})
	defer close()
	tokenData := introspectToken(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", uri)}, "", SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestIntrospect_IssuerMismatch(t *testing.T) {
	uri, close := createIntrospectMockServer(introspectResponse{Active: true, Iss: "other"})
	defer close()
	tokenData := introspectToken(Options{BaseURI: uri, Debug: true}, cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", uri)}, "", SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestIntrospect_AudMismatch(t *testing.T) {
	uri, close := createIntrospectMockServer(introspectResponse{Active: true, Aud: "other"}, true)
	defer close()
	tokenData := introspectToken(Options{BaseURI: uri, Debug: true, ClientID: "clientID"}, cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", uri)}, "", SecurityOptions{})
	assert.Nil(t, tokenData)
}

func TestIntrospect_Success(t *testing.T) {
	uri, close := createIntrospectMockServer(introspectResponse{Active: true, Aud: "clientID", Sub: "sub"}, true)
	defer close()
	tokenData := introspectToken(Options{BaseURI: uri, Debug: true, ClientID: "clientID"}, cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", uri)}, "", SecurityOptions{})
	assert.NotNil(t, tokenData)
	assert.Equal(t, "sub", tokenData.Sub)
	assert.Equal(t, "clientID", tokenData.Aud)
}

func TestIntrospect_VerifyPassedData(t *testing.T) {
	secOpts := SecurityOptions{
		Roles:                 []string{"role1"},
		Scopes:                []string{"scope1"},
		Groups:                []GroupValidationOptions{{GroupID: "groupID"}},
		StrictGroupValidation: true,
		StrictScopeValidation: false,
		StrictRoleValidation:  true,
		StrictValidation:      true,
	}
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		req := &introspectRequest{}
		json.NewDecoder(r.Body).Decode(&req)
		defer r.Body.Close()
		assert.Equal(t, secOpts.Roles, req.Roles)
		assert.Equal(t, secOpts.Scopes, req.Scopes)
		assert.Equal(t, secOpts.Groups, req.Groups)
		assert.Equal(t, secOpts.StrictGroupValidation, req.StrictGroupValidation)
		assert.Equal(t, secOpts.StrictRoleValidation, req.StrictRoleValidation)
		assert.Equal(t, secOpts.StrictScopeValidation, req.StrictScopeValidation)
		assert.Equal(t, secOpts.StrictValidation, req.StrictValidation)
		assert.Equal(t, "token", req.Token)
		assert.Equal(t, "clientID", req.ClientID)
		json.NewEncoder(w).Encode(introspectResponse{Active: true, Aud: "clientID", Sub: "sub", Iss: mockServer.URL})
	})
	mockServer = httptest.NewServer(mockHandler)
	tokenData := introspectToken(Options{BaseURI: mockServer.URL, Debug: true, ClientID: "clientID"}, cidaasEndpoints{IntrospectionEndpoint: fmt.Sprintf("%v/introspect", mockServer.URL)}, "token", secOpts)
	assert.NotNil(t, tokenData)
	assert.Equal(t, "sub", tokenData.Sub)
	assert.Equal(t, "clientID", tokenData.Aud)
}

func createIntrospectMockServer(res introspectResponse, setURI ...bool) (string, func()) {
	var mockServer *httptest.Server
	mockHandler := http.NewServeMux()
	mockHandler.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		if len(setURI) != 0 {
			res.Iss = mockServer.URL
		}
		json.NewEncoder(w).Encode(res)
	})
	mockServer = httptest.NewServer(mockHandler)
	return mockServer.URL, func() { mockServer.Close() }
}
