package servestd

import (
	"net/http"
	"net/url"

	"example.com/bench/common"
)

type httpHandlerPair struct {
	http.ResponseWriter
	*http.Request
}

var sinks []*common.Sink

func newHandler() http.HandlerFunc {
	for _, s := range sinks {
		if s.Handler == nil {
			s.Handler = common.GenericHandler(s)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		for _, s := range sinks {
			in := common.GetUserInput(r)
			s.Handler("unsafe", in, httpHandlerPair{w, r})
		}
	}
}

func RegisterRoutes() {
	sinks = append(sinks, &common.Sink{
		Name:     "http.Redirect",
		Sanitize: url.PathEscape,
		VulnerableFnWrapper: func(opaque interface{}, payload string) (string, error) {
			p := opaque.(httpHandlerPair)
			http.Redirect(p.ResponseWriter, p.Request, payload, http.StatusFound)
			return "", nil
		},
	})
	http.HandleFunc("/", newHandler())
}

// direct, baseline
func direct(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, common.GetUserInput(r), http.StatusFound)
}
