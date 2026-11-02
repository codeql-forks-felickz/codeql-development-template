package servechi

import (
	"log"
	"net/http"
	"net/url"

	"example.com/bench/common"
	"github.com/go-chi/chi/v5"
)

type httpHandlerPair struct {
	http.ResponseWriter
	*http.Request
}

func newHandler(v common.Route) func(w http.ResponseWriter, r *http.Request) {
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
}

func Setup() *chi.Mux {
	RegisterRoutes()
	router := chi.NewRouter()
	for _, rt := range common.AllRoutes {
		for _, s := range rt.Sinks {
			if s.Handler == nil {
				var err error
				s.Handler, err = common.GenericHandler(s)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
		router.Get(rt.Base+"/{sink}/{mode}", newHandler(rt))
	}
	return router
}
