# AngularJS client-side template injection

AngularJS (1.x) compiles the DOM below an element marked with `ng-app` when the application bootstraps. Any `{{ }}` expression found in text nodes or attribute values is evaluated as an AngularJS expression. If a page writes user-controlled data into that part of the DOM before (or while) AngularJS compiles it, an attacker can inject an expression such as `{{constructor.constructor('alert(1)')()}}`. Older AngularJS versions have known sandbox escapes, and from AngularJS 1.6 there is no sandbox at all, so this leads to arbitrary JavaScript execution in the application origin.

HTML-encoding the data (for example with jQuery `.text()`, `textContent` or `innerText`) does not help: the curly braces are not HTML control characters, so they survive encoding and are then interpreted by AngularJS. For this reason the standard `js/xss` query does not treat these text sinks as dangerous.

## Recommendation

Do not mix server- or URL-derived data with AngularJS template compilation:

- Render user data through AngularJS data binding (for example `ng-bind` or `{{ value }}` bound to a scope variable) instead of writing it into the DOM before compilation.
- Mark regions that display untrusted text with `ng-non-bindable`.
- If neither is possible, remove or encode the `{` and `}` characters before writing the value.

## Example

The following login page reads the `user` query parameter and writes it into the page with jQuery `.text()`. The text is HTML-encoded, but because the `<body>` carries `ng-app`, AngularJS evaluates any expression the attacker places in the parameter:

```html
<body ng-app="">
  <h2 id="message"></h2>
  <script>
    var user = new URLSearchParams(window.location.search).get('user');
    $('#message').text("Failed authentication attempt for " + user + "!");
  </script>
</body>
```

Strip the curly braces (or, better, bind the value through AngularJS) to fix the problem:

```html
<body ng-app="">
  <h2 id="message"></h2>
  <script>
    var user = new URLSearchParams(window.location.search).get('user');
    $('#message').text("Failed authentication attempt for " + user.replace(/[{}]/g, '') + "!");
  </script>
</body>
```

## Limitations

- Only scripts that are inline in, or loaded via a resolvable `<script src>` from, an HTML file that contains an `ng-app` (or `data-ng-app`, `x-ng-app`, `ng:app`, `ng_app`) attribute are considered.
- The query does not check whether the DOM write happens before AngularJS compiles the page or whether the targeted element lies inside the `ng-app` element; writes performed only after bootstrap (for example in event handlers) are not compiled and are false positives.
- Sinks are limited to DOM text writes (jQuery `.text()`, `textContent`, `innerText` and `document.createTextNode`). HTML sinks such as `innerHTML` are covered by `js/xss`.

## References

- AngularJS: [Security - Mixing client-side and server-side templates](https://docs.angularjs.org/guide/security#mixing-client-side-and-server-side-templates).
- PortSwigger: [Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-94](https://cwe.mitre.org/data/definitions/94.html).
- Common Weakness Enumeration: [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html).
