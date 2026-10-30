# Server-side request forgery through an external fetch command

Some applications fetch remote resources by running `curl` or `wget` with `ProcessBuilder` or
`Runtime.exec`. If the URL comes from the request, an attacker can make the server fetch
arbitrary resources, including cloud metadata endpoints and internal services, and often read
the response. The standard `java/ssrf` query only models Java HTTP client APIs, so these
fetches are not reported as request forgery.

The query reports user input that reaches:

- an argument after the program name when the program is `curl` or `wget` (with or without a
  path), in an array, argument list or varargs call
- a command string that starts with `curl` or `wget`, such as the script passed to `sh -c` or
  the single string passed to `Runtime.exec`, including command strings stored in local variables

Input that is appended after a constant that fixes the scheme and host of the URL, for example
`"curl -s https://images.example.com/thumbs/" + name`, is not reported. Neither is input checked
against an allowlist with the sanitizers recognized by `java/ssrf`.

Values passed separately to known output options (`--output`, `-o`, `--output-document` or `-O`)
are not treated as fetch targets.

## Known limitations

The query recognizes separate-argument output options. It does not parse attached option values
or every tool-specific option, so some non-target arguments may still be reported.

When the command goes through a shell, `java/command-line-injection` usually reports the same
location as CWE-78. This query adds the request forgery classification and also covers argument
arrays that are not shell commands.

## Recommendation

Use a Java HTTP client instead of an external process, and validate the URL before fetching it.
Allow only expected schemes (`http`, `https`), resolve the host and reject private, loopback and
link-local addresses, and prefer a fixed allowlist of hosts. Disable redirects or validate each
redirect target.

## Example

The following endpoint passes the `url` parameter to curl through a shell:

```java
@GetMapping("/image")
public String image(@RequestParam String url) throws Exception {
  String[] command = {"/bin/sh", "-c", "curl --silent -S " + url + " --output /tmp/img.jpg"};
  new ProcessBuilder(command).start().waitFor();
  ...
}
```

The following version only fetches images from a fixed host:

```java
@GetMapping("/image")
public String image(@RequestParam String name) throws Exception {
  if (!name.matches("[A-Za-z0-9_-]+\\.jpg")) {
    throw new IllegalArgumentException();
  }
  new ProcessBuilder("curl", "--silent", "-S", "--output", "/tmp/img.jpg",
      "https://images.example.com/" + name).start().waitFor();
  ...
}
```

## References

- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
