/**
 * @name Failure to use secure cookies
 * @description Insecure cookies may be sent in cleartext, which makes them vulnerable to
 *              interception. This variant also reports framework settings (Flask and Django
 *              configuration, and aiohttp-session storage options) that explicitly disable
 *              the `Secure` flag of session and CSRF cookies.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id py/custom/insecure-cookie
 * @tags security
 *       external/cwe/cwe-614
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts
import FrameworkCookieSettings

from Http::Server::CookieWrite cookie, string message
where
  cookie.hasSecureFlag(false) and
  isSensitiveCookie(cookie) and
  if cookie instanceof FrameworkCookieSetting
  then
    message =
      "Setting '" + cookie.(FrameworkCookieSetting).getSettingName() +
        "' disables the 'secure' flag of the " +
        cookie.(FrameworkCookieSetting).getCookieDescription() + "."
  else message = "Cookie is added to response without the 'secure' flag being set."
select cookie, message
