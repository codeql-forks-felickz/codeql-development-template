// Package jsonapi stores handlers and their content type in struct fields, like
// package common, but only ever uses a JSON content type.
package jsonapi

import (
	"fmt"
	"net/http"
)

type Endpoint struct {
	Fn   func(string) string
	Mime string
}

var endpoints = []*Endpoint{
	{
		Fn:   func(s string) string { return `{"echo":"` + s + `"}` },
		Mime: "application/json",
	},
}

func handler(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("input")
	for _, e := range endpoints {
		w.Header().Set("Content-Type", e.Mime)
		fmt.Fprint(w, e.Fn(in)) // OK: the content type is never HTML
	}
}

// Setup registers the handler.
func Setup() {
	http.HandleFunc("/api", handler)
}
