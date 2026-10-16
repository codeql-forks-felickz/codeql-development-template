# Reflected cross-site scripting in an ERB script block

Rails HTML-escapes the output of `<%= ... %>` directives. This escaping only encodes `&`, `<`, `>`, `"` and `'`, so it is not enough when the value is written into JavaScript code inside a `<script>` element. If the value is not inside a quoted string literal, an attacker can supply input such as `1);alert(document.cookie);(1` that contains none of the escaped characters but still changes the script. Inside a template literal (backticks), `${...}` can be used in the same way.

This query complements the standard `rb/reflected-xss` query, which only reports output that is not HTML-escaped (for example `raw`, `html_safe` or `<%== ... %>`). It reports request input that reaches an HTML-escaping `<%= ... %>` directive inside a `<script>` element, unless the directive is inside a single- or double-quoted string literal on the same line.

## Recommendation

Do not write user input directly into JavaScript code. Convert values that should be numbers with `to_i` or `to_f`, serialize other values as JSON with `to_json` (which also escapes `<`, `>` and `&`), or put the value in a `data-` attribute and read it from the script.

## Example

In the following example, the `admin_id` route parameter is inserted into a JavaScript expression. A request for a URL whose `admin_id` is `1);alert(document.cookie);(1` runs the attacker's script in the browser of the administrator who opens the link:

```erb
<script>
function loadTable() {
  $("#userDataTable").load("/admin/" + <%= params[:admin_id] %> + "/get_all_users");
}
</script>
```

The fixed version converts the parameter to a number before writing it into the script:

```erb
<script>
function loadTable() {
  $("#userDataTable").load("/admin/" + <%= params[:admin_id].to_i %> + "/get_all_users");
}
</script>
```

## References

- OWASP: [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Rails: [Cross-Site Scripting (XSS)](https://guides.rubyonrails.org/security.html#cross-site-scripting-xss).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
