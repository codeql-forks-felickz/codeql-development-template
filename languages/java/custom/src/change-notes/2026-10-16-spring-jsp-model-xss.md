---
category: newQuery
---
* Added a new query, `java/xss-spring-jsp-model-attribute`, to detect cross-site scripting where user input is added to a Spring MVC model (`Model`, `ModelMap` or `ModelAndView`) and rendered by a JSP view. The standard `java/xss` query does not analyze JSP pages and so does not report this flow. The query only reports results when the application configures a JSP view resolver.
