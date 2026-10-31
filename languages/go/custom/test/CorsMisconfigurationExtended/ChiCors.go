package main

import (
	"net/http"

	chicors "github.com/go-chi/cors"
)

// BAD: any http(s) origin may issue state-changing requests.
func chiWildcardMethods() func(http.Handler) http.Handler {
	return chicors.Handler(chicors.Options{
		AllowedOrigins: []string{"https://*", "http://*"}, // $ Alert
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	})
}

// GOOD: a fixed, trusted origin.
func chiFixedOrigin() func(http.Handler) http.Handler {
	return chicors.Handler(chicors.Options{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowCredentials: true,
	})
}
