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

// BAD: an optional closing slash in its own group is still a blocklist.
func blocklistOptionalGroup(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=optionalgroup
	re := regexp.MustCompile(`<\s*(/\s*)?script[^>]*>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=optionalgroup
}

// BAD: a whitespace character class before the tag name is still a blocklist.
func blocklistWhitespaceClass(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=whitespaceclass
	re := regexp.MustCompile(`<[ \t]*script`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=whitespaceclass
}

// BAD: a POSIX whitespace class before the tag name is still a blocklist.
func blocklistPosixWhitespace(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=posixwhitespace
	re := regexp.MustCompile(`<[[:space:]]*script[^>]*>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=posixwhitespace
}

// BAD: literal whitespace before the tag name is still a blocklist.
func blocklistLiteralWhitespace(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=literalwhitespace
	re := regexp.MustCompile(`< *script[^>]*>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=literalwhitespace
}

// BAD: bounded whitespace before the tag name is still a blocklist.
func blocklistBoundedWhitespace(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=boundedwhitespace
	re := regexp.MustCompile(`<\s{0,3}script[^>]*>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=boundedwhitespace
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

// OK: every tag is removed.
func stripLazyTags(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q")
	re := regexp.MustCompile(`<.*?>`)
	w.Write([]byte(re.ReplaceAllString(in, "")))
}

// BAD: a word-character tag pattern does not remove tags with attributes.
func stripWordTags(w http.ResponseWriter, r *http.Request) {
	in := r.FormValue("q") // $ Source=wordtags
	re := regexp.MustCompile(`<\w+>`)
	w.Write([]byte(re.ReplaceAllString(in, ""))) // $ Alert=wordtags
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
	http.HandleFunc("/blocklist-optional-group", blocklistOptionalGroup)
	http.HandleFunc("/blocklist-whitespace-class", blocklistWhitespaceClass)
	http.HandleFunc("/blocklist-posix-whitespace", blocklistPosixWhitespace)
	http.HandleFunc("/blocklist-literal-whitespace", blocklistLiteralWhitespace)
	http.HandleFunc("/blocklist-bounded-whitespace", blocklistBoundedWhitespace)
	http.HandleFunc("/strip-all-tags", stripAllTags)
	http.HandleFunc("/strip-all-tags-escaped-slash", stripAllTagsEscapedSlash)
	http.HandleFunc("/strip-lazy-tags", stripLazyTags)
	http.HandleFunc("/strip-word-tags", stripWordTags)
	http.HandleFunc("/strip-metachars", stripMetachars)
	http.HandleFunc("/escaped", escaped)
}
