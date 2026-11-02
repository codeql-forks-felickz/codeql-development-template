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

func rsSequentialFieldWrites(h http.Handler) http.Handler {
	options := cors.Options{}
	options.AllowedOrigins = []string{"*"} // $ Alert
	options.AllowCredentials = true
	return cors.New(options).Handler(h)
}

func rsReassignedConfig(h http.Handler) http.Handler {
	options := cors.Options{AllowedOrigins: []string{"*"}}
	options = cors.Options{
		AllowedOrigins:   []string{"https://example.com"},
		AllowCredentials: true,
	}
	return cors.New(options).Handler(h)
}

func rsMutuallyExclusiveWrites(h http.Handler, allowWildcard bool) http.Handler {
	options := cors.Options{}
	if allowWildcard {
		options.AllowedOrigins = []string{"*"}
	} else {
		options.AllowCredentials = true
	}
	return cors.New(options).Handler(h)
}

func rsAllowOriginFunc(h http.Handler) http.Handler {
	options := cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://example.com"
		},
	}
	return cors.New(options).Handler(h)
}

func rsAllowOriginRequestFunc(h http.Handler) http.Handler {
	options := cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowOriginRequestFunc: func(_ *http.Request, origin string) bool {
			return origin == "https://example.com"
		},
	}
	return cors.New(options).Handler(h)
}

func rsAllowOriginVaryRequestFunc(h http.Handler) http.Handler {
	options := cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		AllowOriginVaryRequestFunc: func(_ *http.Request, origin string, _ http.Header) (bool, []string) {
			return origin == "https://example.com", nil
		},
	}
	return cors.New(options).Handler(h)
}
