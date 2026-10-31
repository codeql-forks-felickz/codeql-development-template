---
category: minorAnalysis
---

- Added `html-injection` sink models for `print`, `println` and `write` on `javax.servlet.jsp.JspWriter` and `jakarta.servlet.jsp.JspWriter`, the `out` object of a JSP page. `java/xss` now reports untrusted data written by JSP scriptlets and `<%= %>` expressions, provided the JSP pages are compiled to Java (for example with `jspc`) during the CodeQL build. CodeQL does not extract `.jsp` files directly. Values read from a database (`ResultSet.getString`) are only reported when the `database` threat model is enabled.
