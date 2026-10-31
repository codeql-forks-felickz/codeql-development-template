# Third-party script loaded without Subresource Integrity

Pages often load JavaScript libraries from third-party hosts, such as public content delivery networks (CDNs). The browser runs these scripts with the full privileges of the page. If the third-party host, its DNS, or the delivery path is compromised, or a published package version is replaced, an attacker can run arbitrary code in every page that includes the script. That code can steal session data and act on behalf of authenticated users.

[Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) (SRI) lets the browser check that a fetched script matches a known cryptographic hash before it runs the script.

This query reports `<script>` elements in HTML (including HTML-based templates such as `.html.erb`) that load a script from a public package CDN, or a version-pinned `.js` file from another third-party host, without a non-empty `integrity` attribute. It does not report scripts that are already reported by `js/functionality-from-untrusted-source` or `js/functionality-from-untrusted-domain`.

## Recommendation

Add an `integrity` attribute containing the hash of the expected file to every version-pinned third-party script, together with `crossorigin="anonymous"`. You can also serve the script from your own origin, for example by bundling it with your application assets.

## Example

The following page loads jQuery from a CDN without an integrity check:

```html
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
```

The fixed version includes the SRI hash of the expected file:

```html
<script
  src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
  integrity="sha384-(base64-encoded SHA-384 hash of jquery.min.js)"
  crossorigin="anonymous"
></script>
```

## References

- MDN: [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).
- W3C: [Subresource Integrity](https://www.w3.org/TR/SRI/).
- Common Weakness Enumeration: [CWE-829](https://cwe.mitre.org/data/definitions/829.html).
- Common Weakness Enumeration: [CWE-353](https://cwe.mitre.org/data/definitions/353.html).
