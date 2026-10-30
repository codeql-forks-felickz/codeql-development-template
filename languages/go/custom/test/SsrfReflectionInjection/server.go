package main

import (
	htmltemplate "html/template"
	"net/http"
	"text/template"
)

func badTextTemplateFromQuery(w http.ResponseWriter, r *http.Request) {
	tpl := r.URL.Query().Get("tpl") // $ Source[go/template-injection]
	t, err := template.New("page").Parse(tpl) // $ Alert[go/template-injection]
	if err != nil {
		return
	}
	t.Execute(w, Person("Gus"))
}

func badHtmlTemplateFromForm(w http.ResponseWriter, r *http.Request) {
	tpl := "<p>" + r.FormValue("tpl") + "</p>" // $ Source[go/template-injection]
	t := htmltemplate.New("page")
	t, _ = t.Parse(tpl) // $ Alert[go/template-injection]
	t.Execute(w, Person("Gus"))
}

func goodConstantTemplateWithQueryData(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	t := template.Must(template.New("page").Parse("Hello {{.}}"))
	t.Execute(w, name)
}

func goodAllowListedTemplate(w http.ResponseWriter, r *http.Request) {
	templates := map[string]string{
		"greeting": "Hello {{.Label \"world\"}}",
	}
	tpl, ok := templates[r.URL.Query().Get("name")]
	if !ok {
		return
	}
	t := template.Must(template.New("page").Parse(tpl))
	t.Execute(w, Person("Gus"))
}

func init() {
	http.HandleFunc("/a", badTextTemplateFromQuery)
	http.HandleFunc("/b", badHtmlTemplateFromForm)
	http.HandleFunc("/c", goodConstantTemplateWithQueryData)
	http.HandleFunc("/d", goodAllowListedTemplate)
}
