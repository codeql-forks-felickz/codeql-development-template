// This is a minimal stub of github.com/labstack/echo, strictly for use in testing.

package echo

type Context interface{}

type HandlerFunc func(Context) error

type MiddlewareFunc func(HandlerFunc) HandlerFunc

type Echo struct {
	HideBanner bool
}

func New() *Echo { return nil }

func (_ *Echo) Use(_ ...MiddlewareFunc) {}
