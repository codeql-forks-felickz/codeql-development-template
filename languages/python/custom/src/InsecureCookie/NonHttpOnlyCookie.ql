/**
 * @name Sensitive cookie missing `HttpOnly` attribute
 * @description Cookies without the `HttpOnly` attribute set can be accessed by JS scripts, making
 *              them more vulnerable to XSS attacks. This variant also reports framework settings
 *              (Flask and Django configuration, and aiohttp-session storage options) that
 *              explicitly disable the `HttpOnly` flag of session cookies.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id py/custom/client-exposed-cookie
 * @tags security
 *       external/cwe/cwe-1004
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts
import FrameworkCookieSettings

from Http::Server::CookieWrite cookie, string message
where
  cookie.hasHttpOnlyFlag(false) and
  isSensitiveCookie(cookie) and
  if cookie instanceof FrameworkCookieSetting
  then
    message =
      "Setting '" + cookie.(FrameworkCookieSetting).getSettingName() +
        "' disables the 'HttpOnly' flag of the " +
        cookie.(FrameworkCookieSetting).getCookieDescription() + "."
  else message = "Sensitive server cookie is set without HttpOnly flag."
select cookie, message
