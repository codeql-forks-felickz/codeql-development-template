# XML external entity expansion in libxmljs-compatible parsers

The standard `js/xxe` query models the `libxmljs` package only. The `libxml` and `libxmljs2` packages expose the same `parseXml` / `parseXmlString` API, and with the `noent: true` option they expand external entities. Parsing untrusted XML this way lets an attacker read local files or cause denial of service.

This query reuses the standard `js/xxe` taint configuration and reports only flows that reach a `libxml` or `libxmljs2` parser, so it does not duplicate `js/xxe` alerts.

XXE parsers cannot be added through a data extension because `js/xxe` has no `sinkModel` kind. Its sinks come from the QL class `XML::ParserInvocation`.

## Recommendation

Do not enable `noent` when parsing untrusted XML.

## Example

```javascript
const libxmljs = require('libxml')

router.post('/upload-products', (req, res) => {
  // BAD: external entities are expanded
  libxmljs.parseXmlString(req.files.products.data, { noent: true })

  // GOOD: entity expansion is disabled (default)
  libxmljs.parseXmlString(req.files.products.data)
})
```

## References

- OWASP: [XML External Entity (XXE) Processing](<https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing>)
- Common Weakness Enumeration: [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-827](https://cwe.mitre.org/data/definitions/827.html)
