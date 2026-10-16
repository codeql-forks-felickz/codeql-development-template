# Stored cross-site scripting (including ActiveRecord collections)

Directly writing an uncontrolled stored value (for example, a database field) to a webpage, without properly sanitizing the value first, allows for a cross-site scripting vulnerability.

This query extends the standard `rb/stored-xss` query. The standard query treats fields read from a single ActiveRecord record returned by a finder method (such as `find`, `find_by` or `first`) as stored values. This variant additionally treats fields read from each record yielded by iterating an ActiveRecord relation (built with methods such as `all`, `where`, `order` or `limit`) using `each`, `map`, `find_each` and similar methods as stored values, including when the relation is assigned to a controller instance variable and iterated in the associated ERB view.

## Recommendation

To guard against stored cross-site scripting, escape stored values before writing them to the page. In Rails views, the default `<%= ... %>` output is HTML-escaped. Avoid `raw`, `html_safe` and `<%== ... %>` for values that may have been stored by a user, or sanitize them first with `sanitize`, `html_escape` or a similar helper.

## Example

In the following example, the controller loads all of the current user's todos with `where`, and the view renders each todo's `body` (which was created from request parameters) with `raw`. A todo body such as `<img src=x onerror=alert(1)>` executes in the browser of anyone viewing the list:

```ruby
class TodosController < ApplicationController
  def index
    @todos = Todo.where(user_id: current_user.id)
  end
end
```

```erb
<% @todos.each do |todo| %>
  <li><%= raw(todo.body) %></li>
<% end %>
```

The fixed version relies on the default HTML escaping:

```erb
<% @todos.each do |todo| %>
  <li><%= todo.body %></li>
<% end %>
```

## References

- OWASP: [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Rails: [Cross-Site Scripting (XSS)](https://guides.rubyonrails.org/security.html#cross-site-scripting-xss).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
