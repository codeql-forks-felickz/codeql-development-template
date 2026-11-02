/**
 * @name Unauthenticated access to state-changing endpoint
 * @description Using `permitAll()` for a state-changing HTTP method (POST, PUT,
 *              PATCH or DELETE) on an endpoint that is not part of the
 *              authentication flow lets anyone invoke it without authentication.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id java/spring-security-permit-all-state-changing
 * @tags security
 *       external/cwe/cwe-306
 */

import java

/** A call to `requestMatchers`, `antMatchers`, `mvcMatchers` or `regexMatchers` with a state-changing `HttpMethod`. */
class StateChangingMatcherCall extends MethodCall {
  string httpMethod;

  StateChangingMatcherCall() {
    this.getMethod().hasName(["requestMatchers", "antMatchers", "mvcMatchers", "regexMatchers"]) and
    this.getMethod()
        .getDeclaringType()
        .getSourceDeclaration()
        .getPackage()
        .getName()
        .matches("org.springframework.security.%") and
    exists(Field f |
      f = this.getArgument(0).(FieldAccess).getField() and
      f.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpMethod") and
      httpMethod = f.getName() and
      httpMethod = ["POST", "PUT", "PATCH", "DELETE"]
    )
  }

  /** Gets the HTTP method matched by this call. */
  string getHttpMethod() { result = httpMethod }

  /** Gets a constant path pattern argument of this call. */
  CompileTimeConstantExpr getAPathArgument() {
    exists(int i | i > 0 | result = this.getArgument(i) and exists(result.getStringValue()))
  }
}

/** Holds if `path` looks like an endpoint that must be reachable before authentication. */
bindingset[path]
predicate isAuthenticationFlowPath(string path) {
  path.regexpMatch("(?i).*(log-?in|log-?out|sign-?in|sign-?up|register|registration|auth|token|password|forgot|reset|verify|confirm|activate|oauth|saml|sso|csrf|error|health).*")
}

from
  MethodCall permitAll, StateChangingMatcherCall matcher, CompileTimeConstantExpr pathArg,
  string path
where
  permitAll.getMethod().hasName("permitAll") and
  permitAll
      .getMethod()
      .getDeclaringType()
      .getSourceDeclaration()
      .getPackage()
      .getName()
      .matches("org.springframework.security.%") and
  permitAll.getQualifier() = matcher and
  pathArg = matcher.getAPathArgument() and
  path = pathArg.getStringValue() and
  not isAuthenticationFlowPath(path)
select pathArg,
  "Unauthenticated " + matcher.getHttpMethod() + " requests to '" + path + "' are permitted by $@.",
  permitAll, "permitAll()"
