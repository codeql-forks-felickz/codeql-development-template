// Package gin is a minimal stub of github.com/gin-gonic/gin for testing.
package gin

import "net/http"

type HandlerFunc func(*Context)

type Context struct {
	Request *http.Request
	Writer  http.ResponseWriter
}

func (c *Context) Query(key string) string                               { return "" }
func (c *Context) PostForm(key string) string                            { return "" }
func (c *Context) Param(key string) string                               { return "" }
func (c *Context) GetHeader(key string) string                           { return "" }
func (c *Context) Cookie(name string) (string, error)                    { return "", nil }
func (c *Context) Redirect(code int, location string)                    {}
func (c *Context) String(code int, format string, values ...interface{}) {}

type Engine struct{}

func Default() *Engine                                             { return &Engine{} }
func (e *Engine) GET(relativePath string, handlers ...HandlerFunc) {}
