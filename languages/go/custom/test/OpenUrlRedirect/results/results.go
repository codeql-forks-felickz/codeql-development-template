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

type Redirector struct {
	w http.ResponseWriter
	r *http.Request
}

func (d *Redirector) BoundRedirect(target string) {
	http.Redirect(d.w, d.r, target, http.StatusFound) // $ Alert
}

func (d *Redirector) ExpressionRedirect(target string) {
	http.Redirect(d.w, d.r, target, http.StatusFound) // $ Alert
}

type RedirectActions struct {
	Bound      func(string)
	Expression func(*Redirector, string)
}

func methodValues(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("next") // $ Source
	redirector := &Redirector{w, r}
	actions := &RedirectActions{
		Bound:      redirector.BoundRedirect,
		Expression: (*Redirector).ExpressionRedirect,
	}
	actions.Bound(in)
	actions.Expression(redirector, in)
}
