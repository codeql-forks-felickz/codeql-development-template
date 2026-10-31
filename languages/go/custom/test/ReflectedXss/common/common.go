// Package common is a framework-agnostic sink registry, in the style of a
// vulnerable-application benchmark: each sink stores the vulnerable function in
// a function-typed struct field, and the content type for raw responses in a
// string field.
package common

import (
	"fmt"
	"net/http"
)

type Safety string

const (
	Safe   Safety = "safe"
	Unsafe Safety = "unsafe"
)

type HandlerFn func(safety Safety, payload string, opaque interface{}) (data, mime string, status int)

type VulnerableFnWrapper func(opaque interface{}, payload string) (data string, raw bool, err error)

type Sink struct {
	Name                string
	Handler             HandlerFn
	Sanitize            func(string) string
	VulnerableFnWrapper VulnerableFnWrapper
	// the mime type used when VulnerableFnWrapper returns true for raw; defaults to text/plain.
	RawMime string
}

type Route struct {
	Base  string
	Sinks []*Sink
}

var AllRoutes []Route

func Register(r Route) { AllRoutes = append(AllRoutes, r) }

func GetUserInput(r *http.Request) string {
	if v := r.URL.Query().Get("input"); v != "" { // $ Source=bench
		return v
	}
	return r.FormValue("input") // $ Source=bench
}

// GenericHandler adapts a VulnerableFnWrapper to a HandlerFn.
func GenericHandler(s *Sink) (HandlerFn, error) {
	return func(safety Safety, payload string, opaque interface{}) (data, mime string, status int) {
		mime = "text/plain"
		if safety == Safe {
			payload = s.Sanitize(payload)
		}
		res, raw, err := s.VulnerableFnWrapper(opaque, payload)
		if raw {
			if len(s.RawMime) > 0 {
				mime = s.RawMime
			}
			return res, mime, http.StatusOK
		}
		e := "(no error)"
		if err != nil {
			e = err.Error()
		}
		data = fmt.Sprintf("%q: action with payload=%q resulted in err=%s and data=%s", s.Name, payload, e, res)
		return data, mime, http.StatusOK
	}, nil
}
