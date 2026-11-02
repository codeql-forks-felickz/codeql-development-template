package main

import (
	"net/http"

	echov4 "github.com/labstack/echo/v4"
	mwv4 "github.com/labstack/echo/v4/middleware"
)

// BAD: wildcard origin with credentials.
func echoV4WildcardCredentials() {
	e := echov4.New()
	e.Use(mwv4.CORSWithConfig(mwv4.CORSConfig{
		AllowOrigins:     []string{"*"}, // $ Alert
		AllowCredentials: true,
	}))
}

// BAD: wildcard origin and credentials set field by field.
func echoV4FieldWrites() {
	cfg := mwv4.CORSConfig{AllowOrigins: []string{"https://*"}} // $ Alert
	cfg.AllowCredentials = true
	echov4.New().Use(mwv4.CORSWithConfig(cfg))
}

// GOOD: wildcard origin, but only safe methods.
func echoV4WildcardSafeMethods() {
	e := echov4.New()
	e.Use(mwv4.CORSWithConfig(mwv4.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead},
	}))
}

// GOOD: wildcard origin, credentials disabled, no explicit methods.
func echoV4WildcardOnly() {
	e := echov4.New()
	e.Use(mwv4.CORSWithConfig(mwv4.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: false,
	}))
	e.Use(mwv4.CORS())
}

// GOOD: a fixed, trusted origin with credentials.
func echoV4FixedOrigin() {
	e := echov4.New()
	e.Use(mwv4.CORSWithConfig(mwv4.CORSConfig{
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{http.MethodPut, http.MethodDelete},
		AllowCredentials: true,
	}))
}
