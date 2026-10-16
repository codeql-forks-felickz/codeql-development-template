# Template engine HTML autoescaping disabled

Server-side template engines such as Swig, Nunjucks and Handlebars HTML-escape interpolated values by default. Disabling that behavior (`autoescape: false` for Swig and Nunjucks, `noEscape: true` for Handlebars) means every `{{ value }}` in every affected template is written to the page verbatim. Any value that can contain user-controlled data, including data previously stored in a database, then becomes a cross-site scripting vulnerability.

The stock `js/reflected-xss` and `js/stored-xss` queries do not report these cases because the flow into the template is not modeled as an HTML sink when escaping is turned off globally.

## Recommendation

Keep autoescaping enabled. If a specific value must be rendered as HTML, sanitize it with a well-tested HTML sanitizer and mark only that value as safe (for example with the engine's `safe` filter).

## Example

The following configuration disables escaping for every Swig template rendered by the application:

```javascript
const swig = require("swig");
swig.setDefaults({ autoescape: false });
```

Remove the option, or set it to `true`:

```javascript
swig.setDefaults({ autoescape: true });
```

## References

- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Nunjucks: [configure options](https://mozilla.github.io/nunjucks/api.html#configure).
- Handlebars: [compile options](https://handlebarsjs.com/api-reference/compilation.html).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
