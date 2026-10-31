package servestd

import (
	"log"
	"net/http"
	"net/url"

	"example.com/bench/common"
)

type httpHandlerPair struct {
	http.ResponseWriter
	*http.Request
}

func newHandler(v common.Route) http.HandlerFunc {
	for _, s := range v.Sinks {
		if s.Handler == nil {
			var err error
			s.Handler, err = common.GenericHandler(s)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, s := range v.Sinks {
			in := common.GetUserInput(r)
			s.Handler(common.Unsafe, in, httpHandlerPair{w, r})
		}
	}
}

func RegisterRoutes() {
	common.Register(&common.Sink{
		Name:     "http.Redirect",
		Sanitize: url.PathEscape,
		VulnerableFnWrapper: func(opaque interface{}, payload string) (data string, raw bool, err error) {
			p, ok := opaque.(httpHandlerPair)
			if !ok {
				log.Fatalf("'opaque': want httpHandlerPair, got %T", opaque)
			}
			w, r := p.ResponseWriter, p.Request
			http.Redirect(w, r, payload, http.StatusFound) // $ Alert
			return "", true, nil
		},
	})
	for _, r := range common.AllRoutes {
		http.HandleFunc(r.Base+"/", newHandler(r))
	}
}

// Baseline: a direct redirect is already reported by the standard query.
func direct(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound) // $ Alert
}

// Safe: redirect to the request's own path (a safe part of the request URL).
func trailingSlash(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
}
