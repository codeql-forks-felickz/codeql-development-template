package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Reduced from a synthetic benchmark app: request input reaches file-system
// sinks only through function values stored in struct fields.

type Safety string

const (
	Safe   Safety = "safe"
	Unsafe Safety = "unsafe"
)

type HandlerFn func(safety Safety, payload string, opaque interface{}) (data string, status int)

type VulnerableFnWrapper func(opaque interface{}, payload string) (data string, err error)

type Sink struct {
	Name                string
	Handler             HandlerFn
	Sanitize            func(string) string
	VulnerableFnWrapper VulnerableFnWrapper
}

type Route struct {
	Base  string
	Sinks []*Sink
}

var AllRoutes []Route

func Register(r Route) {
	AllRoutes = append(AllRoutes, r)
}

func GenericHandler(s *Sink) HandlerFn {
	return func(safety Safety, payload string, opaque interface{}) (string, int) {
		if safety == Safe {
			payload = s.Sanitize(payload)
		}
		res, err := s.VulnerableFnWrapper(opaque, payload)
		if err != nil {
			return err.Error(), http.StatusBadRequest
		}
		return res, http.StatusOK
	}
}

func RegisterRoutes() {
	Register(Route{
		Base: "pathTraversal",
		Sinks: []*Sink{
			{Name: "os.ReadFile", Sanitize: url.QueryEscape, VulnerableFnWrapper: osReadFile},
			{Name: "os.Open", Sanitize: url.QueryEscape, VulnerableFnWrapper: osOpen},
			{Name: "os.WriteFile", Sanitize: url.QueryEscape, VulnerableFnWrapper: osWriteFile},
			{Name: "os.Create", Sanitize: url.QueryEscape, VulnerableFnWrapper: osCreate},
		},
	})
}

func osReadFile(_ interface{}, payload string) (string, error) {
	content, err := os.ReadFile(payload) // $ Alert
	return string(content), err
}

func osOpen(_ interface{}, payload string) (string, error) {
	f, err := os.Open(payload) // $ Alert
	if err != nil {
		return "", err
	}
	defer f.Close()
	return "", nil
}

func osWriteFile(_ interface{}, payload string) (string, error) {
	return "", os.WriteFile(payload, []byte("x"), 0644) // $ Alert
}

func osCreate(_ interface{}, payload string) (string, error) {
	f, err := os.Create(payload) // $ Alert
	if err != nil {
		return "", err
	}
	defer f.Close()
	return "", nil
}

func GetUserInput(r *http.Request) string {
	if v := r.URL.Query().Get("input"); v != "" { // $ Source
		return v
	}
	return r.FormValue("input") // $ Source
}

func newHandler(v Route) http.HandlerFunc {
	for _, s := range v.Sinks {
		if s.Handler == nil {
			s.Handler = GenericHandler(s)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		elems := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		for _, s := range v.Sinks {
			if elems[1] != s.Name {
				continue
			}
			in := GetUserInput(r)
			data, status := s.Handler(Safety(elems[2]), in, nil)
			w.WriteHeader(status)
			fmt.Fprint(w, data)
			return
		}
	}
}

// Negative cases.

type FileOps struct {
	Read  func(name string) ([]byte, error)
	Audit func(name string) ([]byte, error)
}

var ops = FileOps{Read: confinedRead, Audit: auditRead}

// Reached with user input, but rejects any path containing "..".
func confinedRead(name string) ([]byte, error) {
	if strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid path")
	}
	return os.ReadFile(filepath.Join("/srv/data", name)) // safe: sanitized
}

// Stored in a different field of the same function type; only called with a constant.
func auditRead(name string) ([]byte, error) {
	return os.ReadFile(name) // safe: never receives user input
}

func opsHandler(w http.ResponseWriter, r *http.Request) {
	ops.Read(r.URL.Query().Get("file")) // safe: confinedRead sanitizes
	ops.Audit("/var/log/audit.log")
}

func main() {
	http.HandleFunc("/ops", opsHandler)
	RegisterRoutes()
	for _, r := range AllRoutes {
		http.HandleFunc("/"+r.Base+"/", newHandler(r))
	}
	http.ListenAndServe(":8080", nil)
}
