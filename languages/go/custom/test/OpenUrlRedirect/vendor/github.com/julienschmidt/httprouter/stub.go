// Package httprouter is a minimal stub of github.com/julienschmidt/httprouter for testing.
package httprouter

import "net/http"

type Param struct {
	Key   string
	Value string
}

type Params []Param

type Handle func(http.ResponseWriter, *http.Request, Params)

type Router struct{}

func New() *Router                               { return &Router{} }
func (r *Router) GET(path string, handle Handle) {}
