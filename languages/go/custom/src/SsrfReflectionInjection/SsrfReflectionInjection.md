# Server-side template injection

Go's `text/template` and `html/template` packages evaluate template actions against the data value passed to `Execute`. A template can read exported fields and call exported methods of that value, and can call template functions such as `call` and `printf`. If the template text itself comes from a user, the user decides which methods are invoked and with which arguments. When the data value has methods with side effects (for example a method that runs a command or reads a file), this leads to code execution or information disclosure. `html/template` escapes output but does not restrict which methods a template can call.

## Recommendation

Do not parse user input as template text. Use fixed templates that are part of the application, and pass user input only as the data argument to `Execute`. If users must choose between templates, look the template up from a fixed allow-list.

## Example

The following program parses a template read from standard input and executes it with a `Person` value. An attacker can supply `{{.Secret "id"}}` to run an arbitrary command:

```go
reader := bufio.NewReader(os.Stdin)
text, _ := reader.ReadString('\n')
tmpl, _ := template.New("").Parse(text)
tmpl.Execute(os.Stdout, Person("Gus"))
```

The fixed version uses a constant template and passes the user input as data:

```go
reader := bufio.NewReader(os.Stdin)
text, _ := reader.ReadString('\n')
tmpl := template.Must(template.New("").Parse("Hello {{.}}"))
tmpl.Execute(os.Stdout, text)
```

Note: standard input is a `local` threat-model source. Enable it with `--threat-model local` (or the equivalent code scanning configuration) to report the example above. Remote sources such as HTTP request parameters are reported by default.

## References

- Go documentation: [text/template](https://pkg.go.dev/text/template).
- OWASP: [Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection).
- Common Weakness Enumeration: [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
