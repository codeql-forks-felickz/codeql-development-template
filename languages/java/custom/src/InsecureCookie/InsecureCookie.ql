/**
 * @name Failure to use secure cookies
 * @description Insecure cookies may be sent in cleartext, which makes them vulnerable to
 *              interception.
 * @kind problem
 * @problem.severity error
 * @security-severity 4.0
 * @precision high
 * @id java/insecure-cookie
 * @tags security
 *       external/cwe/cwe-614
 */

/*
 * Customized variant of the upstream `java/insecure-cookie` query. In addition to servlet
 * `Cookie` objects (unchanged upstream logic), it reports Spring `ResponseCookie`s that are built
 * without `.secure(true)` and raw `Set-Cookie` header values without the `Secure` attribute.
 */

import java
import semmle.code.java.frameworks.Servlets
import semmle.code.java.security.InsecureCookieQuery
import Cookies.SpringCookies

from MethodCall add, string message
where
  add.getMethod() instanceof ResponseAddCookieMethod and
  not SecureCookieFlow::flowToExpr(add.getArgument(0)) and
  message = "Cookie is added to response without the 'secure' flag being set."
  or
  exists(CookieResponseSink sink |
    isResponseCookieWithoutSecure(sink) and
    add = sink.getCall() and
    message = "Cookie is added to response without the 'secure' flag being set."
  )
  or
  exists(SetCookieHeaderValue value |
    isRawSetCookieHeaderWithoutSecure(value) and
    add = value.getCall() and
    message = "'Set-Cookie' header is added to response without the 'Secure' attribute."
  )
select add, message
