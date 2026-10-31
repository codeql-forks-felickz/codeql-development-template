package main

import (
	"net/http"

	"github.com/rs/cors"
)

// BAD: wildcard origin with credentials.
func rsWildcardCredentials(h http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // $ Alert
		AllowCredentials: true,
	})
	return c.Handler(h)
}

// GOOD: a fixed, trusted origin.
func rsFixedOrigin(h http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{http.MethodPut, http.MethodDelete},
		AllowCredentials: true,
	})
	return c.Handler(h)
}
