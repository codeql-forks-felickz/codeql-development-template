// Package sessions is a minimal stub of github.com/gin-contrib/sessions for testing.
package sessions

import "net/http"

type Options struct {
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

type Session interface {
	Options(Options)
	Save() error
}

type Store interface {
	Options(Options)
}
