package main

// Request data passed to a handler that is stored in a function-typed struct field and invoked
// through that field. The callee of `s.Handler(...)` cannot be resolved by the call graph, so the
// upstream `go/command-injection` query does not report these.

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
)

type Safety string

const (
	Safe   Safety = "safe"
	Unsafe Safety = "unsafe"
)

type HandlerFn func(mode Safety, payload string, opaque interface{}) (data, mime string, status int)

type Sink struct {
	Name    string
	Handler HandlerFn
	// Audit has the same type as Handler but is never invoked with request data.
	Audit HandlerFn
}

type Route struct {
	Base  string
	Sinks []*Sink
}

var AllRoutes []Route

func Register(r Route) { AllRoutes = append(AllRoutes, r) }

func RegisterRoutes() {
	sinks := []*Sink{
		{Name: "exec.Command", Handler: execHandler, Audit: auditHandler},
		{Name: "exec.CommandContext", Handler: execHandlerCtx},
		{Name: "echo", Handler: func(mode Safety, payload string, _ interface{}) (string, string, int) {
			out, _ := exec.Command("echo", payload).Output() // GOOD: payload is only an argument to echo
			return string(out), "text/plain", http.StatusOK
		}},
	}
	Register(Route{Base: "/cmdInjection", Sinks: sinks})
}

// shellArgs splits the input into an executable and its arguments.
func shellArgs(in string) []string {
	return strings.Fields(in)
}

func execHandler(mode Safety, in string, _ interface{}) (string, string, int) {
	var cmd *exec.Cmd
	switch mode {
	case Safe:
		cmd = exec.Command("echo", in) // GOOD: payload is only an argument to echo
	case Unsafe:
		args := shellArgs(in)
		if len(args) == 0 {
			return "one or more args required", "text/plain", http.StatusBadRequest
		}
		cmd = exec.Command(args[0], args[1:]...) // BAD
	}
	out, _ := cmd.Output()
	return string(out), "text/plain", http.StatusOK
}

func execHandlerCtx(mode Safety, in string, _ interface{}) (string, string, int) {
	args := shellArgs(in)
	if len(args) == 0 {
		return "one or more args required", "text/plain", http.StatusBadRequest
	}
	out, _ := exec.CommandContext(context.Background(), args[0], args[1:]...).Output() // BAD
	return string(out), "text/plain", http.StatusOK
}

// auditHandler is stored in the `Audit` field, which is never called with request data.
func auditHandler(mode Safety, in string, _ interface{}) (string, string, int) {
	exec.Command(in).Run() // GOOD: not reachable from a request through `Sink.Audit`
	return "", "text/plain", http.StatusOK
}

func getUserInput(r *http.Request) string {
	if value := r.URL.Query().Get("input"); value != "" {
		return value
	}
	return r.FormValue("input")
}

func newHandler(v Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, s := range v.Sinks {
			mode := Safety(r.URL.Query().Get("mode"))
			in := getUserInput(r)
			data, _, status := s.Handler(mode, in, r)
			s.Audit(mode, "/usr/bin/logger", nil)
			w.WriteHeader(status)
			w.Write([]byte(data))
		}
	}
}

// A handler assigned to a function-typed field and invoked from another function.
type Job struct {
	Name string
	Run  func(arg string)
}

var job = &Job{Name: "job"}

func runJob(arg string) {
	exec.Command("sh", "-c", arg).Run() // BAD
}

func jobHandler(w http.ResponseWriter, r *http.Request) {
	job.Run(r.FormValue("arg"))
}

func main() {
	job.Run = runJob
	http.HandleFunc("/job", jobHandler)
	RegisterRoutes()
	http.HandleFunc("/api/health", healthHandler)
	http.HandleFunc("/direct", directHandler)
	for _, r := range AllRoutes {
		http.HandleFunc(r.Base+"/", newHandler(r))
	}
	http.ListenAndServe(":8080", nil)
}
