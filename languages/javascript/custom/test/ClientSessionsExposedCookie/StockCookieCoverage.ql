/**
 * Checks stock cookie recognition, sensitivity, and flags without the client-sessions model.
 */

import javascript

from CookieWrites::CookieWrite cookie, string sensitive, string httpOnly
where
  cookie.getFile().getBaseName() = "frameworks.js" and
  (
    cookie.isSensitive() and sensitive = "sensitive"
    or
    not cookie.isSensitive() and sensitive = "public"
  ) and
  (
    cookie.isHttpOnly() and httpOnly = "httpOnly"
    or
    not cookie.isHttpOnly() and httpOnly = "exposed"
  )
select cookie, sensitive, httpOnly
