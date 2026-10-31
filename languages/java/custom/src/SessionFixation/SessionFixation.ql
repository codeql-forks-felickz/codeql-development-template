/**
 * @name Session fixation after login
 * @description Storing authentication state in an existing HTTP session without
 *              renewing the session identifier lets an attacker who knows the
 *              pre-login session ID hijack the authenticated session.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id java/session-fixation
 * @tags security
 *       external/cwe/cwe-384
 */

import java
import semmle.code.java.frameworks.Servlets

/** A call to `HttpServletRequest.getSession()` or `getSession(true)`. */
class GetOrCreateSessionCall extends MethodCall {
  GetOrCreateSessionCall() {
    this.getMethod().hasName("getSession") and
    this.getMethod().getDeclaringType().getASupertype*() instanceof HttpServletRequest and
    not this.getArgument(0).(CompileTimeConstantExpr).getBooleanValue() = false
  }
}

/** A call to `HttpSession.setAttribute` (or `putValue`) storing authentication state. */
class AuthAttributeWrite extends MethodCall {
  AuthAttributeWrite() {
    this.getMethod().hasName(["setAttribute", "putValue"]) and
    this.getMethod()
        .getDeclaringType()
        .getASupertype*()
        .hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpSession") and
    this.getArgument(0)
        .(CompileTimeConstantExpr)
        .getStringValue()
        .regexpMatch("(?i).*(user|login|logged|auth|principal|account|role).*")
  }
}

/** Holds if `c` renews the session identifier, for example after `invalidate()`. */
predicate renewsSessionId(Callable c) {
  exists(MethodCall mc | mc.getEnclosingCallable() = c |
    mc.getMethod().hasName("changeSessionId") and
    mc.getMethod().getDeclaringType().getASupertype*() instanceof HttpServletRequest
    or
    mc.getMethod().hasName("invalidate") and
    mc.getMethod()
        .getDeclaringType()
        .getASupertype*()
        .hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "HttpSession")
  )
}

from GetOrCreateSessionCall getSession, Callable c
where
  c = getSession.getEnclosingCallable() and
  exists(AuthAttributeWrite write |
    write.getQualifier() = getSession or
    write.getQualifier().(VarAccess).getVariable().getAnAssignedValue() = getSession
  ) and
  not renewsSessionId(c)
select getSession,
  "This session stores authentication state without renewing the session identifier, allowing session fixation."
