// Package echo is a minimal stub of github.com/labstack/echo (v3) for testing.
package echo

type Context interface {
	Bind(i interface{}) error
	String(code int, s string) error
}
