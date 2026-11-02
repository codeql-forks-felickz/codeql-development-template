// Package common mirrors the framework-agnostic sink registry used by go-test-bench:
// each sink stores its vulnerable function in a function-typed struct field, and a
// generic handler (itself stored in another function-typed field) invokes it.
package common

import (
	"fmt"
	"net/http"
	"strings"
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
}

type Route struct {
	Base  string
	Sinks []*Sink
}

var AllRoutes []Route

func Register(s *Sink) {
	AllRoutes = append(AllRoutes, Route{Base: "/unvalidated", Sinks: []*Sink{s}})
}

func GenericHandler(s *Sink) (HandlerFn, error) {
	if s.VulnerableFnWrapper == nil {
		return nil, fmt.Errorf("missing VulnerableFnWrapper")
	}
	return func(safety Safety, payload string, opaque interface{}) (data, mime string, status int) {
		if safety == Safe {
			payload = s.Sanitize(payload)
		}
		res, _, err := s.VulnerableFnWrapper(opaque, payload)
		if err != nil {
			return err.Error(), "text/plain", http.StatusBadRequest
		}
		return res, "text/plain", http.StatusOK
	}, nil
}

func GetUserInput(r *http.Request) string {
	if v := r.URL.Query().Get("input"); v != "" { // $ Source
		return v
	}
	if v := r.FormValue("input"); v != "" { // $ Source
		return v
	}
	if v := r.Header.Get("input"); v != "" {
		return v
	}
	// The last path element is a safe part of the request URL for redirects; it
	// must not suppress results for the other (untrusted) inputs above.
	return GetPathValue(r, -1)
}

func GetPathValue(r *http.Request, positions ...int) string {
	splitURL := strings.Split(r.URL.Path, "/")
	var param []string
	for _, v := range positions {
		if v < 0 {
			v = len(splitURL) + v
		}
		param = append(param, splitURL[v])
	}
	return strings.Join(param, "/")
}
