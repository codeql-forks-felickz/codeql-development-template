// This is a minimal stub of github.com/rs/cors, strictly for use in testing.

package cors

import "net/http"

type Options struct {
	AllowedOrigins             []string
	AllowedMethods             []string
	AllowedHeaders             []string
	AllowCredentials           bool
	AllowOriginFunc            func(origin string) bool
	AllowOriginRequestFunc     func(r *http.Request, origin string) bool
	AllowOriginVaryRequestFunc func(r *http.Request, origin string, requestHeader http.Header) (bool, []string)
}

type Cors struct{}

func New(_ Options) *Cors { return nil }

func (_ *Cors) Handler(h http.Handler) http.Handler { return h }

func Handler(_ Options) func(http.Handler) http.Handler { return nil }
