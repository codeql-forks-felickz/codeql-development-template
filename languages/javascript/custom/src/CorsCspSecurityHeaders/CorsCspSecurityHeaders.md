# Cross-origin exposure of user data

Browsers isolate data between origins, but two common patterns bypass that isolation:

- **JSONP with ambient credentials.** A JSONP response (`res.jsonp(...)` in Express) is executed as a script. Any website can include `<script src="https://victim.example/endpoint?callback=f">`, and the browser attaches the victim's cookies to that request. If the response contains data derived from the cookie, session, or authenticated user, the third-party page can read it (cross-site script inclusion, XSSI).
- **`postMessage` with target origin `"*"`.** Data sent with `win.postMessage(data, "*")` is delivered to whatever document is currently loaded in `win`. If the window was navigated to another origin (for example a popup opened with `window.open`, or an iframe), user-entered data is disclosed to that origin.

This query reports `res.jsonp(...)` calls in handlers that read `req.cookies`, `req.signedCookies`, `req.session`, `req.user` or the `Cookie` header, and `postMessage(..., "*")` calls whose message contains data entered by the user in the DOM (such as an input element's `value`).

## Recommendation

Do not serve authenticated data as JSONP. Use plain JSON together with a restrictive CORS policy instead. When using `postMessage`, always pass the exact origin of the intended recipient as the second argument.

## Example

The following handler returns the logged-in user's profile as JSONP when a `callback` parameter is present:

```javascript
app.get('/whoami', (req, res) => {
  const user = sessions.get(req.cookies.token)
  res.jsonp({ email: user.email }) // BAD
})
```

Return JSON instead, which a cross-origin page cannot read unless CORS allows it:

```javascript
app.get('/whoami', (req, res) => {
  const user = sessions.get(req.cookies.token)
  res.json({ email: user.email }) // GOOD
})
```

The following code sends a value typed by the user to a popup without restricting the origin:

```javascript
const popup = window.open('https://scoreboard.example.com/board.html')
popup.postMessage('guess:' + document.getElementById('guess').value, '*') // BAD
```

Pass the expected origin instead:

```javascript
popup.postMessage(
  'guess:' + document.getElementById('guess').value,
  'https://scoreboard.example.com'
) // GOOD
```

## References

- OWASP: [Cross-Site Script Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion).
- MDN: [Window.postMessage()](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage).
- Common Weakness Enumeration: [CWE-346](https://cwe.mitre.org/data/definitions/346.html).
- Common Weakness Enumeration: [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
