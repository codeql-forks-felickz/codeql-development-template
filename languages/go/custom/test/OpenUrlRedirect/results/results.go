package results

import "net/http"

// A function stored in a struct field that returns (a value derived from) its
// argument; the call result should carry the taint of the argument.
type Normalizer struct {
	Normalize func(string) (string, error)
}

func passthrough(s string) (string, error) {
	return "/" + s, nil
}

var norm = []*Normalizer{{Normalize: passthrough}}

func handler(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("next") // $ Source
	for _, n := range norm {
		target, _ := n.Normalize(in)
		http.Redirect(w, r, target, http.StatusFound) // $ Alert
	}
}
