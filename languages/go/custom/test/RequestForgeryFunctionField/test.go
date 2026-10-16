package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type Safety string

const (
	Unsafe Safety = "unsafe"
	NOOP   Safety = "noop"
)

// HandlerFn is a framework-agnostic handler stored in a struct field and
// invoked indirectly, mirroring a common "route table" design.
type HandlerFn func(safety Safety, payload string) (data string, status int)

type Sink struct {
	Name    string
	Handler HandlerFn
	Logger  func(msg string)
}

type Route struct {
	Base  string
	Sinks []*Sink
}

var AllRoutes []Route

func Register(r Route) { AllRoutes = append(AllRoutes, r) }

// Vulnerable: reached only through the `Handler` function-valued field.
func httpHandler(safety Safety, payload string) (string, int) {
	if u, err := url.Parse(payload); err != nil {
		return "bad url", http.StatusBadRequest
	} else if len(u.Scheme) == 0 {
		payload = "http://" + payload
	}
	switch safety {
	case Unsafe:
		resp, err := http.Get(payload) // $ Alert[go/request-forgery-function-field]
		if err != nil {
			return err.Error(), http.StatusInternalServerError
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b), resp.StatusCode
	default:
		return fmt.Sprintf("%s %s", safety, payload), http.StatusOK
	}
}

// Safe: only fetches allow-listed URLs.
func allowListHandler(safety Safety, payload string) (string, int) {
	if payload != "https://example.com/status" {
		return "forbidden", http.StatusForbidden
	}
	resp, err := http.Get(payload)
	if err != nil {
		return err.Error(), http.StatusInternalServerError
	}
	return resp.Status, resp.StatusCode
}

// Safe: the request URL comes from the `safety` parameter, which is never
// tainted at the field call sites below.
func modeHandler(safety Safety, payload string) (string, int) {
	resp, err := http.Get(string(safety))
	if err != nil {
		return err.Error(), http.StatusInternalServerError
	}
	return payload, resp.StatusCode
}

// Never stored in the `Handler` field, only in the unrelated `Logger` field.
func fetchingLogger(msg string) {
	http.Get(msg)
}

func RegisterRoutes() {
	sinks := []*Sink{
		{Name: "net/http", Handler: httpHandler, Logger: fetchingLogger},
		{Name: "allow-list", Handler: allowListHandler},
		{Name: "mode", Handler: modeHandler},
	}
	Register(Route{Base: "/ssrf", Sinks: sinks})
}

// Positive: route table dispatch through a global slice of structs.
func routeTableHandler(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("input") // $ Source[go/request-forgery-function-field]
	for _, route := range AllRoutes {
		for _, s := range route.Sinks {
			data, status := s.Handler(Unsafe, in)
			w.WriteHeader(status)
			fmt.Fprint(w, data)
			s.Logger("handled request")
		}
	}
}

// Positive: function literal assigned to a field, then called via a local alias.
type Client struct {
	Fetch func(target string) error
}

func newClient() *Client {
	c := &Client{}
	c.Fetch = func(target string) error {
		_, err := http.Get(target) // $ Alert[go/request-forgery-function-field]
		return err
	}
	return c
}

func funcLitHandler(w http.ResponseWriter, r *http.Request) {
	c := newClient()
	fetch := c.Fetch
	if err := fetch(r.FormValue("target")); err != nil { // $ Source[go/request-forgery-function-field]
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

// Negative: field call with only constant arguments.
func constantHandler(w http.ResponseWriter, r *http.Request) {
	c := newClient()
	_ = c.Fetch("https://example.com/health")
}

// Baseline: a direct call is already reported by the stock go/request-forgery
// query, so the function-field query does not report it again.
func directFetch(target string) {
	http.Get(target) // $ Alert[go/request-forgery]
}

func directHandler(w http.ResponseWriter, r *http.Request) {
	directFetch(r.URL.Query().Get("target")) // $ Source[go/request-forgery]
}

func main() {
	RegisterRoutes()
	http.HandleFunc("/ssrf/", routeTableHandler)
	http.HandleFunc("/client/", funcLitHandler)
	http.HandleFunc("/const/", constantHandler)
	http.HandleFunc("/direct/", directHandler)
	http.ListenAndServe(":8080", nil)
}
