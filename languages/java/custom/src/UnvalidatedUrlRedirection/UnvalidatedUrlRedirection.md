# URL redirection from remote source (extended)

Directly incorporating user input into a URL redirect request without validating the input can facilitate phishing attacks. In these attacks, unsuspecting users can be redirected to a malicious site that looks very similar to the real site they intend to visit, but which is controlled by the attacker.

This query extends the standard `java/unvalidated-url-redirection` query. In addition to the servlet and other sinks recognized by that query, it reports remote input that controls:

- the target of a Spring MVC redirect view name, for example `return "redirect:" + url;` or `new ModelAndView("redirect:" + url)`;
- a `Location` header on a Spring `HttpHeaders` object (also when held in a `MultiValueMap` variable) or `ResponseEntity` builder, for example `headers.add("Location", url)`, `headers.get("Location").add(url)`, `headers.setLocation(uri)` or `ResponseEntity.status(FOUND).location(uri)`;
- a redirect target that only prepends `"/"`, for example `response.sendRedirect("/" + input)` or `new StringBuilder("/").append(input)`. An input that starts with `/` produces a scheme-relative URL such as `//evil.example`, which browsers treat as an external host.

## Recommendation

To guard against untrusted URL redirection, do not allow arbitrary URLs as redirect targets. Instead, maintain a list of authorized redirects on the server and choose from that list based on the user input. If that is not possible, check that the input is a local path that does not start with `//` or `/\`, or prepend a fixed, non-empty path segment such as `"/app/"`.

## Example

The following Spring controller redirects to a URL taken from a request parameter:

```java
@GetMapping("/support")
public String support(@RequestParam String desk) {
  return "redirect:" + desk; // BAD
}
```

The following code only redirects to an allowlisted destination:

```java
private static final List<String> ALLOWED = Arrays.asList("/home", "/feed");

@GetMapping("/support")
public String support(@RequestParam String desk) {
  if (ALLOWED.contains(desk)) {
    return "redirect:" + desk; // GOOD
  }
  return "redirect:/home";
}
```

## References

- OWASP: [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-601](https://cwe.mitre.org/data/definitions/601.html).
