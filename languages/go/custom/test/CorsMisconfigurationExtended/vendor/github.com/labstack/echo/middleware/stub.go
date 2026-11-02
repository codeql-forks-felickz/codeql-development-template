// This is a minimal stub of github.com/labstack/echo/middleware, strictly for use in testing.

package middleware

import "github.com/labstack/echo"

type CORSConfig struct {
	AllowOrigins                             []string
	AllowOriginFunc                          func(string) (bool, error)
	AllowMethods                             []string
	AllowHeaders                             []string
	AllowCredentials                         bool
	UnsafeWildcardOriginWithAllowCredentials bool
	ExposeHeaders                            []string
	MaxAge                                   int
}

var DefaultCORSConfig = CORSConfig{}

func CORS() echo.MiddlewareFunc { return nil }

func CORSWithConfig(_ CORSConfig) echo.MiddlewareFunc { return nil }
