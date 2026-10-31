package servegin

import (
	"log"
	"net/http"
	"net/url"

	"example.com/bench/common"
	"github.com/gin-gonic/gin"
)

var unvalidatedRedirect = common.Sink{
	Name:     "gin.Redirect",
	Sanitize: url.PathEscape,
	VulnerableFnWrapper: func(opaque interface{}, payload string) (data string, raw bool, err error) {
		c, ok := opaque.(*gin.Context)
		if !ok {
			log.Fatalf("'opaque': want *gin.Context, got %T", opaque)
		}
		c.Redirect(http.StatusFound, payload) // $ Alert
		return "", true, nil
	},
}

func extractInput(c *gin.Context, source string) string {
	switch source {
	case "query":
		return c.Query("input") // $ Source
	case "body":
		return c.PostForm("input") // $ Source
	case "headers":
		return c.GetHeader("input") // $ Source
	default:
		input, _ := c.Cookie("input") // $ Source
		return input
	}
}

func add(router *gin.Engine, rt common.Route) {
	for _, s := range rt.Sinks {
		if s.Handler == nil {
			var err error
			s.Handler, err = common.GenericHandler(s)
			if err != nil {
				log.Fatal(err)
			}
		}
		sinkFn := func(s *common.Sink) func(c *gin.Context) {
			return func(c *gin.Context) {
				mode := common.Safety(c.Param("mode"))
				source := c.Param("source")
				payload := extractInput(c, source)
				data, _, status := s.Handler(mode, payload, c)
				c.String(status, data)
			}
		}(s)
		router.GET(rt.Base+"/"+s.Name+"/:source/:mode", sinkFn)
	}
}

func Setup() *gin.Engine {
	common.Register(&unvalidatedRedirect)
	router := gin.Default()
	for _, rt := range common.AllRoutes {
		add(router, rt)
	}
	return router
}

// Direct use of gin's Context.Redirect with request data.
func directGin(c *gin.Context) {
	c.Redirect(http.StatusFound, c.Query("next")) // $ Alert
}

// Safe: constant redirect target.
func constantGin(c *gin.Context) {
	c.Redirect(http.StatusFound, "/home")
}
