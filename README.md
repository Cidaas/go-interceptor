[![pipeline status](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/badges/master/pipeline.svg)](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/-/commits/master)
[![coverage report](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/badges/master/coverage.svg)](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/-/commits/master)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://gitlab.widas.de/cidaas-public-devkits/cidaas-interceptors/cidaas-go-interceptor/-/blob/master/LICENSE)

# About cidaas:
[cidaas](https://www.cidaas.com) is a fast and secure Cloud Identity & Access Management solution that standardises what’s important and simplifies what’s complex. The cidaas feature set includes:
- Single Sign On (SSO) based on OAuth 2.0, OpenID Connect, SAML 2.0 
- Multi-Factor-Authentication with more than 14 authentication methods, including TOTP and FIDO2 
- Passwordless Authentication 
- Social Login (e.g. Facebook, Google, LinkedIn and more) as well as Enterprise Identity Provider (e.g. SAML or AD) 
- Security in Machine-to-Machine (M2M) and IoT

## How to install

### Version 1.x.x

`go get github.com/Cidaas/go-interceptor`

This version allows to secure your APIs by passing **scopes or roles** to the interceptor which can be either validated by introspecting the access token or checking its signature.

### Version 2.x.x

`go get github.com/Cidaas/go-interceptor/v2`

This version allows to secure your APIs by passing **security options** to the interceptor which can be either validated by introspecting the access token or checking its signature. You can pass the following options to the interceptor:

> For the signature validation only the scopes can be validated in a strict way

```go
// SecurityOptions includes options which restrict the access of the APIs to secure
type SecurityOptions struct {
	Roles                 []string // roles which are allowed to access this api
	Scopes                []string // scopes which are allowed to acces this api
	Groups                []GroupValidationOptions // groups which are allowed to acces this api (only possible with introspect)
	StrictRoleValidation  bool // true indicates that all provided roles must match (only possible with introspect)
	StrictScopeValidation bool // true indicates that all provided scopes must match (also possible with the signature check)
	StrictGroupValidation bool // true indicates that all provided groups must match (only possible with introspect)
	StrictValidation      bool // true indicates that all provided roles, scopes and groups must match (the signature check just checks for the scopes)
}

// GroupValidationOptions provides options to allow API access only to certain groups
type GroupValidationOptions struct {
	GroupID              string   `json:"groupId"`              // the group id to match
	GroupType            string   `json:"groupType"`            // the group type to match
	Roles                []string `json:"roles"`                // the roles to match
	StrictRoleValidation bool     `json:"strictRoleValidation"` // true indicates that all roles must match
	StrictValidation     bool     `json:"strictValidation"`     // true indicates that the group id, group type and all roles must match
}
```

## Usage

The cidaas go interceptor can be used to secure APIs in golang. 

### net/http
The following examples will show how to use the interceptor if you are using the net/http package for your APIs.

**Attached an example how to secure an API with scopes and roles based on the signature of a token:**

#### Version 1.x.x

```go
func get(w http.ResponseWriter, r *http.Request) {
	// set response to ok and return Status ok and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respJSON))
	return
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()
	// Base URI is mandatory, ClientID is optional, if ClientID is set the interceptor will only allow requests from this Client
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID"})
	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}
	getHandler := http.HandlerFunc(get)
	api.Handle("/", cidaasInterceptor.VerifyTokenBySignature(getHandler, []string{"profile", "cidaas:api_scope"}, []string{"role:Admin"})).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

#### Version 2.x.x

```go
func get(w http.ResponseWriter, r *http.Request) {
	// set response to ok and return Status ok and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respJSON))
	return
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v2").Subrouter()
	// Base URI is mandatory, ClientID is optional, if ClientID is set the interceptor will only allow requests from this Client
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID"})
	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}
	getHandler := http.HandlerFunc(get)
	api.Handle("/", cidaasInterceptor.VerifyTokenBySignature(getHandler, SecurityOptions{
		Scopes: []string{"your scope"},
		Roles: []string{"role:Admin"},
	})).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

**Attached an example how to secure an API with scopes and roles based on an introspect call to the cidaas instance:**

#### Version 1.x.x

```go
func get(w http.ResponseWriter, r *http.Request) {
	// set response to ok and return Status ok and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(respJSON))
	return
}

func main() {
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()
	// Base URI is mandatory, ClientID is optional, if ClientID is set the interceptor will only allow requests from this Client
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID")
	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}
	getHandler := http.HandlerFunc(get)
	api.Handle("", cidaasInterceptor.VerifyTokenByIntrospect(getHandler, []string{"profile", "cidaas:api_scope"}, nil)).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

#### Version 2.x.x

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
	// Base URI is mandatory, ClientID is optional, if ClientID is set the interceptor will only allow requests from this Client
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID"})
	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}
	getHandler := http.HandlerFunc(get)
	api.Handle("", cidaasInterceptor.VerifyTokenByIntrospect(getHandler, SecurityOptions{
		Scopes: []string{"your scope"},
		Roles: []string{"role:Admin"},
	})).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

**Attached an example how to secure an API with groups based on an introspect call to the cidaas instance:**

#### Version 1.x.x

> Not supported

#### Version 2.x.x

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
	// Base URI is mandatory, ClientID is optional, if ClientID is set the interceptor will only allow requests from this Client
	cidaasInterceptor, err := cidaasinterceptor.New(cidaasinterceptor.Options{BaseURI: "https://base.cidaas.de", ClientID: "clientID"})
	if err != nil {
		log.Panicf("Initialization of cidaas interceptor failed! Error: %v", err)
		panic("Panic!")
	}
	getHandler := http.HandlerFunc(get)
	api.Handle("", cidaasInterceptor.VerifyTokenByIntrospect(getHandler, SecurityOptions{
		Groups: []GroupValidationOptions{{GroupID: "yourGroupID"}},
	})).Methods(http.MethodGet)
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

### [Fiber](https://github.com/gofiber/fiber)
The following examples will show how to use the interceptor if you are using the fiber web framework for your APIs.

#### How to install

```
go get -u github.com/gofiber/fiber/v2
```

**Attached an example how to secure an API with scopes and roles based on the signature token validation and also with the introspect call:**

#### Version 1.x.x

```go
func CreateApp() (*fiber.App, error) {
	interceptor, err := cidaasinterceptor.NewFiberInterceptor(cidaasinterceptor.Options{
		BaseURI:  BaseUrl,
		ClientID: Client_id,
	})
	if err != nil {
		ls.Fatal().Err(err).Msg("can't initialize interceptor")
	}
	app := fiber.New()
	root := app.Group(fmt.Sprintf("/%s", base.ServiceName))
	root.Post("/user", interceptor.VerifyTokenBySignature([]string{"profile", "cidaas:api_scope"}, []string{"role:Admin"}), handler.UserHandler)
	root.Post("/user", interceptor.VerifyTokenByIntrospect([]string{"profile", "cidaas:api_scope"}, []string{"role:Admin"}), handler.UserHandler)
	return app, nil
}

func main()  {
    app, err := CreateApp()
	if err != nil {
		panic(err)
    }
	app.Listen(":3000")
}
```

#### Version 2.x.x

```go
func CreateApp() (*fiber.App, error) {
	interceptor, err := cidaasinterceptor.NewFiberInterceptor(cidaasinterceptor.Options{
		BaseURI:  BaseUrl,
		ClientID: Client_id,
	})
	if err != nil {
		ls.Fatal().Err(err).Msg("can't initialize interceptor")
	}
	app := fiber.New()
	root := app.Group(fmt.Sprintf("/%s", base.ServiceName))
	root.Post("/user", interceptor.VerifyTokenBySignature(SecurityOptions{
		Scopes: []string{"your scope"},
		Roles: []string{"role:Admin"},
	}), handler.UserHandler)
	root.Post("/user", interceptor.VerifyTokenByIntrospect(SecurityOptions{
		Scopes: []string{"your scope"},
		Roles: []string{"role:Admin"},
	}), handler.UserHandler)
	return app, nil
}

func main()  {
    app, err := CreateApp()
	if err != nil {
		panic(err)
    }
	app.Listen(":3000")
}
```


**Attached an example how to secure an API with groups with the introspect call:**

#### Version 1.x.x

> Not supported

#### Version 2.x.x

```go
func CreateApp() (*fiber.App, error) {
	interceptor, err := cidaasinterceptor.NewFiberInterceptor(cidaasinterceptor.Options{
		BaseURI:  BaseUrl,
		ClientID: Client_id,
	})
	if err != nil {
		ls.Fatal().Err(err).Msg("can't initialize interceptor")
	}
	app := fiber.New()
	root := app.Group(fmt.Sprintf("/%s", base.ServiceName))
	root.Post("/user", interceptor.VerifyTokenByIntrospect(SecurityOptions{
		Groups: []GroupValidationOptions{{GroupID: "yourGroupID"}},
	}), handler.UserHandler)
	return app, nil
}

func main()  {
    app, err := CreateApp()
	if err != nil {
		panic(err)
    }
	app.Listen(":3000")
}
```