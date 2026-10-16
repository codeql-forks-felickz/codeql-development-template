---
category: newQuery
---

- Added a new query, `js/underscore-template-xss`, to detect cross-site scripting where Backbone model data or AJAX response data reaches an unescaped `<%= %>` interpolation in an Underscore/lodash template loaded through the RequireJS `text!` plugin.
