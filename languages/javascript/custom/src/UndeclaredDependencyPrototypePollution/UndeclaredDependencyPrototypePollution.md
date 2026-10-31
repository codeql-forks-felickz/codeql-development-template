# Prototype-polluting merge call with undeclared dependency

Some versions of deep merge libraries, such as `lodash` before 4.17.12 (`merge`, `mergeWith`, `defaultsDeep`, CVE-2019-10744), follow `__proto__` or `constructor.prototype` keys and so let a user-controlled object modify `Object.prototype`.

The stock `js/prototype-pollution` query only reports these calls when a `package.json` declares the library with a vulnerable version. When the library is imported but not declared in any `package.json`, for example in standalone scripts, snippets, or vendored code, its version is unknown and the stock query reports nothing. This query reuses the stock data flow configuration and reports deep merge calls from those libraries when the import has no declared dependency. Because the installed version may be patched, results have medium precision.

## Recommendation

Declare the library in `package.json` with a patched version (for `lodash`, 4.17.12 or later). Where possible, avoid deep merging user-controlled objects, or validate them against an expected schema first.

## Example

```javascript
const lodash = require('lodash') // not declared in any package.json

function check(req, res) {
  let config = {}
  lodash.defaultsDeep(config, JSON.parse(req.body.config)) // BAD if lodash < 4.17.12
}
```

## References

- [CVE-2019-10744](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)
