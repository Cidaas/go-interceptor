package cidaasinterceptor

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func verifySignature(opts Options, endpoints cidaasEndpoints, jwks *Jwks, tokenString string, securityOpts SecurityOptions) *TokenData {
	// parse token
	token, err := jwt.ParseWithClaims(tokenString, &cidaasTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		pem, err := getKey(token, *jwks)
		if err != nil {
			log.Printf("Reloading keys for Kid : %v", token.Header["kid"])
			keys, err := getKeys(endpoints.JwksURI)
			if err != nil {
				return nil, err
			}
			*jwks = keys
			pem, err := getKey(token, *jwks)
			if err == nil {
				return pem, nil
			}
			return nil, fmt.Errorf("no key found for: %v", token.Header["kid"])
		}
		return pem, nil
	})
	// check if there was an error in parsing
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return nil
	}
	sub := ""
	aud := ""
	// check claims
	if claims, ok := token.Claims.(*cidaasTokenClaims); ok && token.Valid {
		if opts.Debug {
			log.Printf("Scopes: %v", claims.Scopes)
			log.Printf("Roles: %v", claims.Roles)
		}
		// verify exp times in token data based on current timestamp
		if !claims.VerifyExpiresAt(time.Now(), true) {
			log.Printf("Token expired!, expiration: %v, now: %v", claims.ExpiresAt, time.Now())
			return nil
		}
		// verify issuer in token data based on baseURI given in options of interceptor
		if !claims.VerifyIssuer(opts.BaseURI, true) {
			log.Printf("Issuer mismatch, issuer: %v, base URI: %v", claims.Issuer, opts.BaseURI)
			return nil
		}
		// check for roles and scopes in token data
		if !checkScopesAndRoles(claims.Scopes, claims.Roles, securityOpts) {
			return nil
		}
		if opts.ClientID != "" {
			if claims.Audience[0] != opts.ClientID {
				log.Printf("Aud mismatch!, aud: %v, clientID: %v", claims.Audience[0], opts.ClientID)
				return nil
			}
		}
		sub = claims.Subject
		aud = claims.Audience[0]
	} else {
		log.Println("Issue with claims")
		return nil
	}
	return &TokenData{Sub: sub, Aud: aud}
}
