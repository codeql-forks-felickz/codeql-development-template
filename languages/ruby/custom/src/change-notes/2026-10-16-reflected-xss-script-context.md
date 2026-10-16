---
category: newQuery
---
* Added a new query, `rb/reflected-xss-script-context`, which finds request input written with an HTML-escaping `<%= ... %>` directive into an unquoted JavaScript context inside an ERB `<script>` element (for example `load("/admin/" + <%= params[:id] %> + "/users")`). The stock `rb/reflected-xss` query treats `<%= ... %>` as safe because it is HTML-escaped, but HTML escaping does not neutralize JavaScript syntax such as `;`, `(` or `${`. Values inside quoted string literals, numeric conversions (`to_i`, `to_f`) and `to_json` are not reported.
