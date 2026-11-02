package main

import (
	"encoding/json"
	"net/http"
)

var allowedOrigins = map[string]bool{"https://example.com": true}

var debugMode = false

// BAD: wildcard origin together with credentials on every JSON response
// (reduced from govwa `util.RenderAsJson`).
func RenderAsJson(w http.ResponseWriter, data ...interface{}) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // $ Alert
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET")
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

// BAD: wildcard origin and state-changing methods are explicitly allowed.
func wildcardWithUnsafeMethods(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // $ Alert
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE")
}

// BAD: same as above, using `Add`.
func wildcardWithUnsafeMethodsAdd(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*") // $ Alert
	w.Header().Add("Access-Control-Allow-Methods", "patch")
}

// GOOD: a public, read-only resource.
func wildcardOnly(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// GOOD: only simple methods are allowed.
func wildcardWithSafeMethods(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

// GOOD: credentials are not allowed.
func wildcardCredentialsFalse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
}

// GOOD: a fixed, trusted origin.
func fixedOrigin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE")
}

// GOOD: the wildcard is only used in debug mode.
func wildcardInDebug(w http.ResponseWriter, r *http.Request) {
	if debugMode {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// BAD: `null` origin with credentials (also reported by `go/cors-misconfiguration`).
func nullOrigin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "null") // $ Alert
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// GOOD: the wildcard and credentials are set on mutually exclusive paths.
func wildcardOrCredentials(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
}

// BAD: reflected origin with credentials (also reported by `go/cors-misconfiguration`).
func reflectedOrigin(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	w.Header().Set("Access-Control-Allow-Origin", origin) // $ Alert
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// GOOD: reflected origin is checked against an allow list.
func checkedOrigin(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

func main() {
	http.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) { RenderAsJson(w, "ok") })
	http.ListenAndServe(":8080", nil)
}
