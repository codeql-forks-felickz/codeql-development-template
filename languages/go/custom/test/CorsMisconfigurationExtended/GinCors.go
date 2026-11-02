package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// BAD: all origins with credentials.
func ginAllowAllOriginsCredentials() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowAllOrigins:  true, // $ Alert
		AllowCredentials: true,
	}))
}

// BAD: wildcard origin with state-changing methods, set field by field.
func ginWildcardMethods() {
	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"} // $ Alert
	config.AllowMethods = []string{"GET", "PUT", "DELETE"}
	router.Use(cors.New(config))
}

// GOOD: all origins, but no credentials and no explicit methods.
func ginAllowAllOriginsOnly() {
	router := gin.Default()
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	router.Use(cors.New(config))
}

// BAD: `null` origin with credentials (also reported by `go/cors-misconfiguration`).
func ginNullOrigin() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"null"}, // $ Alert
		AllowCredentials: true,
	}))
}
