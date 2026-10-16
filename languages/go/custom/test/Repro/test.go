package main

import (
	"io"
	"net/http"
)

type HandlerFn func(mode string, payload string) string

type Sink struct {
	Name    string
	Handler HandlerFn
}

func httpHandler(mode string, payload string) string {
	resp, err := http.Get(payload)
	if err != nil {
		return ""
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

var sinks = []*Sink{{Name: "net/http", Handler: httpHandler}}

func handle(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("input")
	for _, s := range sinks {
		io.WriteString(w, s.Handler("unsafe", in))
	}
}

func main() {
	http.HandleFunc("/ssrf/", handle)
}

func direct(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, httpHandler("unsafe", r.URL.Query().Get("input")))
}

func local(w http.ResponseWriter, r *http.Request) {
	s := &Sink{Handler: httpHandler}
	io.WriteString(w, s.Handler("unsafe", r.URL.Query().Get("input")))
}
