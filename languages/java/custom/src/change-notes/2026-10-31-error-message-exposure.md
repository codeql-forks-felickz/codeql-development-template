---
category: newQuery
---

- Added a new query, `java/custom/error-message-exposure`, which extends the coverage of `java/stack-trace-exposure` and `java/error-message-exposure`. In addition to the upstream results, it reports exception text from `getLocalizedMessage()`, `toString()` and overridden `getMessage()` methods, and treats values stored as Spring MVC model attributes (`Model.addAttribute`, `ModelMap.addAttribute`, `ModelAndView.addObject`) as exposed to the user.
