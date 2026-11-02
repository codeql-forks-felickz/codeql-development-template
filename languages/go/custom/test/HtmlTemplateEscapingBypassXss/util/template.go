package util

import (
	"html/template"
	"net/http"
)

// SafeRender renders a named template from a shared template set.
func SafeRender(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	data["uid"] = "session-user"
	t := template.Must(template.ParseGlob("templates/*"))
	t.ExecuteTemplate(w, name, data) // $ Alert=xss1 Alert=xss2 Alert=alternation
}

// CheckLevel reports whether the high security level is selected.
func CheckLevel(r *http.Request) bool {
	c, err := r.Cookie("Level")
	return err == nil && c.Value == "high"
}
