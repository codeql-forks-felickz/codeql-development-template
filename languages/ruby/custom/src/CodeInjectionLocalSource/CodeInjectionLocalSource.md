# Code injection from local user input

Directly evaluating user input (for example, a command-line argument or a line read from standard input) as code without properly sanitizing it first allows anyone who controls the process input to run arbitrary code. This can happen when the program is invoked by a wrapper script, a CI job, a cron task, or a web front end that forwards untrusted values as process arguments.

The standard `rb/code-injection` query only considers remote flow sources such as HTTP request parameters. This query reuses the same sinks and sanitizers, but treats `ARGV`, `STDIN`, `$stdin`, `ARGF` and `Kernel#gets`/`readline`/`readlines` as sources.

## Recommendation

Avoid including user input in any expression which may be dynamically evaluated. If user input must be included, convert it to the expected type first (for example with `Integer(...)`), or validate it against an allow list of permitted values.

## Example

The following example evaluates two command-line arguments as Ruby code:

```ruby
first_number  = ARGV[0]
second_number = ARGV[1]
print eval(first_number + "+" + second_number)
```

Passing `"system('id')"` as the first argument runs an arbitrary command. Converting the arguments to integers avoids evaluating code entirely:

```ruby
first_number  = Integer(ARGV[0])
second_number = Integer(ARGV[1])
print first_number + second_number
```

## References

- OWASP: [Code Injection](https://www.owasp.org/index.php/Code_Injection).
- Wikipedia: [Code Injection](https://en.wikipedia.org/wiki/Code_injection).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-95](https://cwe.mitre.org/data/definitions/95.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
