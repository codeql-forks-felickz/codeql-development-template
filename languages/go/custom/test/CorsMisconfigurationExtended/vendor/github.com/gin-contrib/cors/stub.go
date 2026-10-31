// This is a minimal stub of github.com/gin-contrib/cors, strictly for use in testing.

package cors

import "github.com/gin-gonic/gin"

type Config struct {
	AllowAllOrigins  bool
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	AllowCredentials bool
}

func DefaultConfig() Config { return Config{} }

func New(_ Config) gin.HandlerFunc { return nil }
