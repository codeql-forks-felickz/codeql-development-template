// Package sessions is a minimal stub of github.com/gorilla/sessions for testing.
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

type Session struct {
	Values  map[interface{}]interface{}
	Options *Options
	IsNew   bool
}

func (s *Session) Save(r *http.Request, w http.ResponseWriter) error { return nil }

type CookieStore struct {
	Options *Options
}

func NewCookieStore(keyPairs ...[]byte) *CookieStore { return nil }

func (s *CookieStore) Get(r *http.Request, name string) (*Session, error) { return nil, nil }

func NewCookie(name, value string, options *Options) *http.Cookie { return nil }
