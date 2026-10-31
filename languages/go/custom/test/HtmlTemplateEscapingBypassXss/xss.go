package main

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"regexp"

	"example.com/escapingbypass/util"
)

// BAD: removing `<script>` tags before wrapping in template.HTML does not stop
// `<img src=x onerror=...>`.
func xss1Handler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	term := r.FormValue("term") // $ Source=xss1
	if util.CheckLevel(r) {
		term = HTMLEscapeString(term)
	}
	term = removeScriptTag(term)
	notFound := fmt.Sprintf("<b><i>%s</i></b> not found", term)
	data["term"] = template.HTML(notFound)
	util.SafeRender(w, r, "template.xss1", data)
}

// BAD: the request value is placed in a script and the script is wrapped in
// template.HTML. The standard query already reports this, at the template
// execution in util.SafeRender.
func xss2Handler(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("uid") // $ Source=xss2
	if util.CheckLevel(r) {
		uid = HTMLEscapeString(uid)
	}
	data := make(map[string]interface{})
	js := `<script>
	var id = %s
	</script>`
	data["inlineJS"] = template.HTML(fmt.Sprintf(js, uid))
	util.SafeRender(w, r, "template.xss2", data)
}

// BAD: an alternation of tag names is still a blocklist.
func alternationHandler(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term") // $ Source=alternation
	re := regexp.MustCompile(`(?i)</?(script|iframe)[^>]*>`)
	data := map[string]interface{}{"term": template.HTML(re.ReplaceAllString(term, ""))}
	util.SafeRender(w, r, "template.alternation", data)
}

// OK: every tag is removed before wrapping in template.HTML.
func stripAllTagsHandler(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	re := regexp.MustCompile("<[^>]*>")
	t := template.Must(template.New("t").Parse("{{.}}"))
	t.Execute(w, template.HTML(re.ReplaceAllString(term, "")))
}

// OK: the value is HTML-escaped before wrapping in template.HTML.
func escapedHandler(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	t := template.Must(template.New("t").Parse("{{.}}"))
	t.Execute(w, template.HTML(HTMLEscapeString(removeScriptTag(term))))
}

// OK: the value is not converted to an unescaped type, so the template escapes it.
func notConvertedHandler(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	t := template.Must(template.New("t").Parse("{{.}}"))
	t.Execute(w, removeScriptTag(term))
}

func HTMLEscapeString(text string) string {
	filter := regexp.MustCompile("<[^>]*>")
	output := filter.ReplaceAllString(text, "")
	return html.EscapeString(output)
}

func removeScriptTag(text string) string {
	filter := regexp.MustCompile("<script*>.*</script>")
	output := filter.ReplaceAllString(text, "")
	return output
}

func main() {
	http.HandleFunc("/xss1", xss1Handler)
	http.HandleFunc("/xss2", xss2Handler)
	http.HandleFunc("/alternation", alternationHandler)
	http.HandleFunc("/strip-all-tags", stripAllTagsHandler)
	http.HandleFunc("/escaped", escapedHandler)
	http.HandleFunc("/not-converted", notConvertedHandler)
	http.ListenAndServe(":8080", nil)
}
