/**
 * @name Insecure authentication, session or web configuration
 * @description Weak ASP.NET authentication, session and web configuration, such as disabled
 *              ViewState integrity, weak password policies, sessions that never expire,
 *              code that keeps running after a redirect, disabled token issuer/audience
 *              validation and disabled account lockout, weakens authentication and session
 *              management.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.9
 * @precision medium
 * @id cs/auth-session-config
 * @tags security
 *       frameworks/asp.net
 *       external/cwe/cwe-287
 *       external/cwe/cwe-307
 *       external/cwe/cwe-521
 *       external/cwe/cwe-554
 *       external/cwe/cwe-613
 *       external/cwe/cwe-698
 */

import csharp
import semmle.code.asp.WebConfig

/** The minimum acceptable password length. */
int minPasswordLength() { result = 8 }

/** The maximum acceptable session or authentication-ticket timeout, in minutes (one day). */
int maxTimeoutMinutes() { result = 1440 }

/** Holds if `value` is a timeout (in minutes) that never expires or is excessively long. */
bindingset[value]
predicate isInsecureTimeout(string value) {
  exists(int t | t = value.trim().toInt() | t <= 0 or t > maxTimeoutMinutes())
}

/** Gets an attribute `name` of a `<system.web>` child `element`, with lower-cased value `value`. */
bindingset[element, name]
private XmlAttribute systemWebAttribute(string element, string name, string value) {
  exists(XmlElement e |
    e = any(SystemWebXmlElement sw).getAChild() and
    e.getName().toLowerCase() = element and
    result = e.getAnAttribute() and
    result.getName().toLowerCase() = name.toLowerCase() and
    value = result.getValue().trim().toLowerCase()
  )
}

/** Holds if `attr` is an insecure ASP.NET `Web.config` setting described by `msg`. */
predicate insecureWebConfig(XmlAttribute attr, string msg) {
  attr = systemWebAttribute("pages", "enableViewStateMac", "false") and
  msg = "ViewState MAC validation is disabled, which allows ViewState tampering (CWE-554)."
  or
  attr = systemWebAttribute("pages", "viewStateEncryptionMode", "never") and
  msg = "ViewState encryption is disabled, which exposes ViewState contents (CWE-554)."
  or
  exists(string v |
    attr = systemWebAttribute("sessionstate", "timeout", v) and
    isInsecureTimeout(v) and
    msg =
      "The session timeout of '" + v +
        "' minutes means sessions never or only rarely expire (CWE-613)."
  )
  or
  exists(FormsElement forms |
    attr = forms.getAttribute("timeout") and
    isInsecureTimeout(attr.getValue()) and
    msg =
      "The forms authentication ticket timeout of '" + attr.getValue().trim() +
        "' minutes means authentication never or only rarely expires (CWE-613)."
  )
  or
  exists(SystemWebXmlElement sw, int len |
    attr = sw.getAChild("membership").getAChild("providers").getAChild("add").getAnAttribute() and
    attr.getName().toLowerCase() = "minrequiredpasswordlength" and
    len = attr.getValue().trim().toInt() and
    len < minPasswordLength() and
    msg =
      "The membership provider accepts passwords of only " + len +
        " characters, which allows easily guessed passwords (CWE-521)."
  )
}

/** Gets a property declared by the type `namespace.type` (or a subtype) with the given name. */
bindingset[namespace, type, name]
Property propertyOf(string namespace, string type, string name) {
  result.hasName(name) and
  result.getDeclaringType().getABaseType*().hasFullyQualifiedName(namespace, type)
}

/** Holds if `a` assigns `value` to a property `p`. */
predicate propertyAssignment(Assignment a, Property p, Expr value) {
  a.getLeftOperand().(PropertyAccess).getTarget() = p and
  value = a.getRightOperand()
}

/** Holds if assignment `a` is an insecure authentication or session setting described by `msg`. */
predicate insecureCodeSetting(Assignment a, string msg) {
  exists(Property p, Expr value | propertyAssignment(a, p, value) |
    (
      p = propertyOf("System.Web.SessionState", "HttpSessionState", "Timeout") or
      p = propertyOf("System.Web", "HttpSessionStateBase", "Timeout")
    ) and
    isInsecureTimeout(value.getValue()) and
    msg =
      "The session timeout of '" + value.getValue() +
        "' minutes means sessions never or only rarely expire (CWE-613)."
    or
    p = propertyOf("Microsoft.AspNetCore.Identity", "PasswordOptions", "RequiredLength") and
    value.getValue().toInt() < minPasswordLength() and
    msg =
      "The password policy accepts passwords of only " + value.getValue() +
        " characters, which allows easily guessed passwords (CWE-521)."
    or
    p = propertyOf("Microsoft.AspNetCore.Identity", "LockoutOptions", "AllowedForNewUsers") and
    value.getValue() = "false" and
    msg =
      "Account lockout is disabled for new users, which allows unlimited password guessing (CWE-307)."
    or
    exists(string name |
      name = ["ValidateIssuer", "ValidateAudience", "ValidateLifetime", "RequireSignedTokens"] and
      p = propertyOf("Microsoft.IdentityModel.Tokens", "TokenValidationParameters", name) and
      value.getValue() = "false" and
      msg =
        "Token validation is weakened by setting '" + name +
          "' to false, so tokens minted for other issuers, audiences or lifetimes are accepted (CWE-287)."
    )
  )
}

/** A call to `Redirect` on an ASP.NET or ASP.NET Core `HttpResponse`. */
class ResponseRedirectCall extends MethodCall {
  ResponseRedirectCall() {
    exists(Method m | m = this.getTarget().getUnboundDeclaration() |
      m.hasName("Redirect") and
      m.getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName(["System.Web", "Microsoft.AspNetCore.Http"],
            ["HttpResponse", "HttpResponseBase"])
    )
  }

  /** Holds if this redirect explicitly ends the response (`endResponse: true`). */
  predicate endsResponse() {
    this.getTarget()
        .getDeclaringType()
        .getABaseType*()
        .hasFullyQualifiedName("System.Web", ["HttpResponse", "HttpResponseBase"]) and
    this.getArgument(1).getValue() = "true"
  }
}

/**
 * Gets the statement that executes next after `s` completes normally, following enclosing
 * blocks, `if`, `using`, `lock` and `try` statements, but not loops or callable bodies.
 */
Stmt getFollowingStmt(Stmt s) {
  exists(BlockStmt b, int i | b.getStmt(i) = s and result = b.getStmt(i + 1))
  or
  not exists(BlockStmt b, int i | b.getStmt(i) = s and exists(b.getStmt(i + 1))) and
  exists(Stmt parent | parent = s.getParent() |
    (
      parent instanceof BlockStmt or
      parent instanceof IfStmt or
      parent instanceof UsingStmt or
      parent instanceof LockStmt or
      parent instanceof TryStmt or
      parent instanceof CatchClause
    ) and
    result = getFollowingStmt(parent)
  )
}

/** Holds if `s` terminates the request or the current method. */
predicate isTerminating(Stmt s) {
  s instanceof ReturnStmt
  or
  s instanceof ThrowStmt
  or
  s instanceof EmptyStmt
  or
  exists(MethodCall c | c = s.(ExprStmt).getExpr() |
    c.getTarget().hasName(["End", "CompleteRequest", "Abort"])
  )
}

/** Holds if `c` is a redirect after which further statements of the request still execute. */
predicate codeAfterRedirect(ResponseRedirectCall c, string msg) {
  not c.endsResponse() and
  exists(Stmt next |
    next = getFollowingStmt(c.getParent().(ExprStmt)) and
    not isTerminating(next)
  ) and
  msg =
    "Execution continues after this redirect without ending the request, so the following code still runs (CWE-698)."
}

private newtype TAlertElement =
  TXmlAttributeAlert(XmlAttribute a) { insecureWebConfig(a, _) } or
  TExprAlert(Expr e) { insecureCodeSetting(e, _) or codeAfterRedirect(e, _) }

/** An element (a `Web.config` attribute or a C# expression) on which an alert is reported. */
class AlertElement extends TAlertElement {
  /** Gets the `Web.config` attribute, if any. */
  XmlAttribute asXmlAttribute() { this = TXmlAttributeAlert(result) }

  /** Gets the C# expression, if any. */
  Expr asExpr() { this = TExprAlert(result) }

  /** Gets a textual representation of this element. */
  string toString() {
    result = this.asXmlAttribute().toString() or result = this.asExpr().toString()
  }

  /** Gets the location of this element. */
  Location getLocation() {
    result = this.asXmlAttribute().getLocation() or result = this.asExpr().getLocation()
  }
}

from AlertElement e, string msg
where
  insecureWebConfig(e.asXmlAttribute(), msg) or
  insecureCodeSetting(e.asExpr(), msg) or
  codeAfterRedirect(e.asExpr(), msg)
select e, msg
