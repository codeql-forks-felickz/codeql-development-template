package filters

import (
	"html"
	"net/http"
	"regexp"
)

func removeScriptTag(text string) string {
	filter := regexp.MustCompile("<script*>.*</script>")
	return filter.ReplaceAllString(text, "")
}

// BAD: removing `<script>` tags does not stop `<img src=x onerror=...>`.
func blocklist(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")               // $ Source=blocklist
	w.Write([]byte(removeScriptTag(in))) // $ Alert=blocklist
}

// BAD: a case-insensitive, whitespace-tolerant `<script>` blocklist is still a blocklist.
func blocklistInline(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=inline
	re := regexp.MustCompile(`(?i)<\s*/?\s*script[^>]*>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=inline
}

// BAD: an alternation of tag names is still a blocklist.
func blocklistAlternation(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=alternation
	re := regexp.MustCompile(`</?(script|iframe)>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=alternation
}

// OK: every tag is removed.
func stripAllTags(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	re := regexp.MustCompile("<[^>]*>")
	w.Write([]byte(re.ReplaceAllString(in, "")))
}

// OK: every tag is removed.
func stripAllTagsEscapedSlash(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	re := regexp.MustCompile(`<\/?[^>]+>`)
	w.Write([]byte(re.ReplaceAllString(in, "")))
}

// OK: every tag made of word characters is removed.
func stripWordTags(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	re := regexp.MustCompile(`<\w+>`)
	w.Write([]byte(re.ReplaceAllString(in, "")))
}

// OK: every HTML meta-character is removed.
func stripMetachars(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	re := regexp.MustCompile(`[<>&"']`)
	w.Write([]byte(re.ReplaceAllString(in, "")))
}

// OK: the value is HTML-escaped.
func escaped(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	w.Write([]byte(html.EscapeString(removeScriptTag(in))))
}

// Setup registers the handlers.
func Setup() {
	http.HandleFunc("/blocklist", blocklist)
	http.HandleFunc("/blocklist-inline", blocklistInline)
	http.HandleFunc("/blocklist-alternation", blocklistAlternation)
	http.HandleFunc("/strip-all-tags", stripAllTags)
	http.HandleFunc("/strip-all-tags-escaped-slash", stripAllTagsEscapedSlash)
	http.HandleFunc("/strip-word-tags", stripWordTags)
	http.HandleFunc("/strip-metachars", stripMetachars)
	http.HandleFunc("/escaped", escaped)
}
