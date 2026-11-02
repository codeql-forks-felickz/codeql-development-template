// Package chi is a minimal stub of github.com/go-chi/chi/v5 for testing.
package chi

import "net/http"

type Mux struct{}

func NewRouter() *Mux                                          { return &Mux{} }
func (mx *Mux) Get(pattern string, handlerFn http.HandlerFunc) {}
