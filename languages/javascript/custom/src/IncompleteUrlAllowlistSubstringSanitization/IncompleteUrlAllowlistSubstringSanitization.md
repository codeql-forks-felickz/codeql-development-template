# Incomplete URL substring sanitization against an allowlist

Checking whether an unparsed URL contains, starts with, or ends with an entry of a URL allowlist does not restrict the URL to the allowlisted hosts. An attacker can put an allowlisted entry anywhere in a URL that points at a host they control, for example in the query string: `https://evil.example/?next=https://github.com/example-org/example-app`.

This query complements `js/incomplete-url-substring-sanitization`, which only reports checks against constant substrings. It reports checks whose substring is an element of an array or `Set` literal of URLs, either as the iteration variable of a `for-of` loop or as the parameter of a callback passed to an array method such as `some` or `find`.

## Recommendation

Parse the URL and compare its origin or host against the allowlist, or compare the whole URL for equality (for example with `Set.prototype.has`). If a prefix check is required, make sure every allowlist entry ends with a `/` after the host.

## Example

The following check accepts any URL that merely contains an allowlisted entry:

```javascript
const redirectAllowlist = new Set(['https://github.com/example-org/example-app'])

function isRedirectAllowed (url) {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

Compare the whole URL instead:

```javascript
function isRedirectAllowed (url) {
  return redirectAllowlist.has(url)
}
```

## References

- OWASP: [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Common Weakness Enumeration: [CWE-601](https://cwe.mitre.org/data/definitions/601.html).
