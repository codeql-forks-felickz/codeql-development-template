package echo

import "net/http"

type Context interface {
	SetCookie(*http.Cookie)
}
