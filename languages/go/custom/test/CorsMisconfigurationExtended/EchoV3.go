package main

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

// BAD: any origin may issue state-changing requests
// (reduced from secDevLabs comment-killer `api/main.go`).
func echoV3Wildcard() {
	e := echo.New()
	e.HideBanner = true
	DefaultCORSConfig := middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // $ Alert
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}
	e.Use(middleware.CORSWithConfig(DefaultCORSConfig))
}

// GOOD: a fixed, trusted origin.
func echoV3FixedOrigin() {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:40001"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
	}))
}
