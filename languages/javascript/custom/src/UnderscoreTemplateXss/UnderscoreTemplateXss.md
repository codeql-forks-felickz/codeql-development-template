# Client-side cross-site scripting through an unescaped Underscore template interpolation

Underscore and lodash templates support two interpolation delimiters. `<%- value %>` HTML-escapes the value, while `<%= value %>` inserts it as raw HTML. When a template is filled with data that an attacker can influence, such as Backbone model data loaded from the server or the body of an AJAX response, using `<%= %>` allows the attacker to inject markup and script into the page.

Note that this is the opposite of EJS, where `<%=` escapes and `<%-` does not.

## Recommendation

Use the escaping delimiter `<%- %>` for any value that is not trusted HTML, or wrap the value in `_.escape(...)`.

## Example

The following Backbone view renders a list of users that it fetched from the server. The template interpolates the username with `<%= %>`, so a user who registers with a name such as `<img src=x onerror=alert(1)>` runs script in the browser of every administrator who opens the page.

```javascript
define(['backbone', 'underscore', 'text!templates/admin_panel.html'], function (
  Backbone,
  _,
  AdminTemplate
) {
  return Backbone.View.extend({
    render: function () {
      var t = _.template(AdminTemplate)
      this.$el.html(t({ users: this.collection.toJSON() }))
    }
  })
})
```

```html
<% _(users).each(function(user) { %>
<td><%= user.username %></td>
<% }); %>
```

Use the escaping delimiter instead:

```html
<td><%- user.username %></td>
```

## Limitations

- Only templates loaded through the RequireJS `text!` plugin and compiled with `_.template` are analyzed. Inline template strings and custom `_.templateSettings` delimiters are not supported.
- Loop variables are recognized textually for `_(c).each(function(e) {`, `_.each(c, function(e) {` and `c.forEach(function(e) {` scriptlets.
- Value types are unknown, so a numeric model field interpolated with `<%= %>` is also reported.
- Every Backbone model or collection in a view (`this.model`, `this.collection`) is treated as potentially attacker-controlled.

## References

- Underscore.js: [template](https://underscorejs.org/#template).
- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
