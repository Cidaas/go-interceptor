[![pipeline status](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/badges/master/pipeline.svg)](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/-/commits/master)
[![coverage report](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/badges/master/coverage.svg)](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/-/commits/master)

# About cidaas:
[cidaas](https://www.cidaas.com) is a fast and secure Cloud Identity & Access Management solution that standardises what’s important and simplifies what’s complex. The cidaas feature set includes:
- Single Sign On (SSO) based on OAuth 2.0, OpenID Connect, SAML 2.0 
- Multi-Factor-Authentication with more than 14 authentication methods, including TOTP and FIDO2 
- Passwordless Authentication 
- Social Login (e.g. Facebook, Google, LinkedIn and more) as well as Enterprise Identity Provider (e.g. SAML or AD) 
- Security in Machine-to-Machine (M2M) and IoT

## How to install

`go get github.com/Cidaas/go-interceptor`

## Usage

The cidaas go interceptor can be used to secure APIs in golang. 

**Attached an example how to secure an API with scopes and roles based on the signature of a token:**

```go

func get(w http.ResponseWriter, r *http.Request) {
    ...
	// set response to ok and return Status ok and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respJSON))
	return
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID", ClientSecret: "clientSecret"})

	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}

	getHandler := http.HandlerFunc(get)
	api.Handle("", cidaasInterceptor.VerifyTokenBySignature(getHandler, []string{"profile", "cidaas:api_scope"}, nil)).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}

```

**Attached an example how to secure an API with scopes and roles based on on an introspect call to the cidaas instance:**

```go

func get(w http.ResponseWriter, r *http.Request) {
    ...
	// set response to ok and return Status ok and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respJSON))
	return
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID", ClientSecret: "clientSecret"})

	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}

	getHandler := http.HandlerFunc(get)
	api.Handle("", cidaasInterceptor.VerifyTokenByIntrospect(getHandler, []string{"profile", "cidaas:api_scope"}, nil)).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}

```
