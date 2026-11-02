package negatives

import (
	"net/http"
	"strings"
)

type pair struct {
	w http.ResponseWriter
	r *http.Request
}

// Each field holds a different stored function; only data passed to a field call
// may reach the functions stored in that same field.
type Actions struct {
	Jump   func(p pair, target string)
	Notify func(p pair, msg string)
	Check  func(p pair, target string)
	Clean  func(target string) string
}

var actions = &Actions{
	// Redirects, but is only ever called with a constant.
	Jump: func(p pair, target string) {
		http.Redirect(p.w, p.r, target, http.StatusFound)
	},
	// Receives user input, but does not redirect.
	Notify: func(p pair, msg string) {
		p.w.Write([]byte(strings.ToUpper(msg)))
	},
	// Receives user input, but only redirects to an allow-listed value.
	Check: func(p pair, target string) {
		if target == "/dashboard" {
			http.Redirect(p.w, p.r, target, http.StatusFound)
		}
	},
	// Returns a constant regardless of its argument.
	Clean: func(target string) string {
		return "/home"
	},
}

func handler(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("next")
	p := pair{w, r}
	actions.Jump(p, "/home")
	actions.Notify(p, in)
	actions.Check(p, in)
	http.Redirect(w, r, actions.Clean(in), http.StatusFound)
}

type redirectReceiver string

func (redirectReceiver) Redirect(target string) {
	http.Redirect(nil, nil, target, http.StatusFound)
}

type receiverActions struct {
	Redirect func(redirectReceiver, string)
}

var methodExpressionActions = &receiverActions{
	Redirect: redirectReceiver.Redirect,
}

func methodExpressionReceiverIsNotTarget(r *http.Request) {
	in := r.URL.Query().Get("next")
	methodExpressionActions.Redirect(redirectReceiver(in), "/home")
}
