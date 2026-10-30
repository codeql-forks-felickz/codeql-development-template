package main

import (
	"bufio"
	htmltemplate "html/template"
	"log"
	"os"
	"os/exec"
	"text/template"
)

type Person string

func (p Person) Secret(test string) string {
	out, _ := exec.Command(test).CombinedOutput()
	return string(out)
}

func (p Person) Label(test string) string {
	return "This is " + string(test)
}

func badHtmlTemplateFromStdin() {
	reader := bufio.NewReader(os.Stdin) // $ Source[go/template-injection]
	text, _ := reader.ReadString('\n')
	tmpl, err := htmltemplate.New("").Parse(text) // $ Alert[go/template-injection]
	if err != nil {
		log.Fatalf("Parse: %v", err)
	}
	tmpl.Execute(os.Stdout, Person("Gus"))
}

func badTextTemplateFromStdin() {
	reader := bufio.NewReader(os.Stdin) // $ Source[go/template-injection]
	text, _ := reader.ReadString('\n')
	tmpl := template.Must(template.New("t").Parse(text)) // $ Alert[go/template-injection]
	tmpl.Execute(os.Stdout, Person("Gus"))
}

func goodConstantTemplateWithStdinData() {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	tmpl := template.Must(template.New("t").Parse("Hello {{.}}"))
	// User input is only passed as data, never parsed as template text.
	tmpl.Execute(os.Stdout, text)
}

func main() {
	badHtmlTemplateFromStdin()
	badTextTemplateFromStdin()
	goodConstantTemplateWithStdinData()
}
