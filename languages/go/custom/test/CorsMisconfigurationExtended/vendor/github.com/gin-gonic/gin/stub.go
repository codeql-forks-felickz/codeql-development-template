// This is a minimal stub of github.com/gin-gonic/gin, strictly for use in testing.

package gin

type HandlerFunc func(*Context)

type Context struct{}

type Engine struct{}

func Default() *Engine { return nil }

func (_ *Engine) Use(_ ...HandlerFunc) {}
