# XPath query built from user-controlled sources (extended)

## Overview

If an XPath expression is built from user-provided input without proper escaping, a malicious user can change the meaning of the expression, for example to select other nodes or to extract data character by character with boolean predicates.

This query extends `py/xpath-injection`. It uses the same sources, sinks and sanitizers, and additionally tracks user-controlled values through local variables that are defined by iterable unpacking (for example `path, query = self.path.split("?", 1)`) and then read in a nested scope, such as a generator expression, comprehension, lambda or inner function. The standard variable-capture flow only starts from definitions with a single assigned value, so such reads are not tainted by `py/xpath-injection`.

## Recommendation

Do not build XPath expressions with string formatting or concatenation. Pass user input as an XPath variable instead, for example with the keyword arguments of `lxml.etree` `xpath()`.

## Example

In the following request handler, `query` is defined by tuple unpacking and is read inside the generator expression that builds `params`. The `name` parameter is then interpolated into an XPath expression:

```python
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split("?", 1) if "?" in self.path else (self.path, "")
        params = dict(
            (m.group("name"), urllib.parse.unquote(",".join(re.findall(r"%s=([^&]+)" % re.escape(m.group("name")), query))))
            for m in re.finditer(r"(?P<name>\w+)=[^&]+", query)
        )
        doc.xpath(".//user[name/text()='%s']" % params["name"])  # BAD
```

Pass the value as an XPath variable instead:

```python
        doc.xpath(".//user[name/text()=$name]", name=params["name"])  # GOOD
```

## References

- OWASP: [XPATH Injection](https://owasp.org/www-community/attacks/XPATH_Injection).
- lxml: [The xpath() method](https://lxml.de/xpathxslt.html#the-xpath-method).
- Common Weakness Enumeration: [CWE-643](https://cwe.mitre.org/data/definitions/643.html).
