package common

import "net/http"

type HandlerFn func(safety string, payload string, opaque interface{}) (data string)

type VulnerableFnWrapper func(opaque interface{}, payload string) (data string, err error)

type Sink struct {
	Name                string
	Handler             HandlerFn
	Sanitize            func(string) string
	VulnerableFnWrapper VulnerableFnWrapper
}

func GenericHandler(s *Sink) HandlerFn {
	return func(safety string, payload string, opaque interface{}) string {
		if safety == "safe" {
			payload = s.Sanitize(payload)
		}
		res, _ := s.VulnerableFnWrapper(opaque, payload)
		return res
	}
}

func GetUserInput(r *http.Request) string {
	if v := r.URL.Query().Get("input"); v != "" {
		return v
	}
	return r.FormValue("input")
}
