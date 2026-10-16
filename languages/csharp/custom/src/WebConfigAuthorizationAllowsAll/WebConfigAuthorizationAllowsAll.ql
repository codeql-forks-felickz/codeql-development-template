/**
 * @name Web.config authorization allows all users
 * @description An application that configures Forms or Windows authentication, but whose
 *              application-wide `<authorization>` rules allow every user (including anonymous
 *              users) without denying anonymous access, leaves its pages reachable without
 *              authentication.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cs/web/config-authorization-allows-all
 * @tags security
 *       external/cwe/cwe-284
 *       external/cwe/cwe-862
 */

import csharp
import semmle.code.asp.WebConfig

/** Gets the lower-case `users` attribute value of the authorization rule `rule`, split by comma. */
private string getAUser(XmlElement rule) {
  result = rule.getAttributeValue("users").splitAt(",").trim().toLowerCase()
}

/** Holds if `rule` is an `<allow>` or `<deny>` element (selected by `kind`) that applies to all or anonymous users. */
private predicate isAllOrAnonymousRule(XmlElement rule, string kind) {
  rule.getName().toLowerCase() = kind and
  getAUser(rule) = ["*", "?"]
}

/** An application-wide `<authorization>` element, that is, one that is not inside a `<location>`. */
class RootAuthorizationXmlElement extends XmlElement {
  RootAuthorizationXmlElement() {
    this.getName().toLowerCase() = "authorization" and
    this.getParent().(SystemWebXmlElement).getParent() instanceof ConfigurationXmlElement and
    this.getFile() instanceof WebConfigXml
  }
}

/** Holds if `f` configures Forms or Windows authentication. */
predicate configuresAuthentication(WebConfigXml f) {
  exists(XmlElement auth |
    auth.getFile() = f and
    auth.getName().toLowerCase() = "authentication" and
    auth.getParent() instanceof SystemWebXmlElement and
    auth.getAttributeValue("mode").toLowerCase() = ["forms", "windows"]
  )
}

from RootAuthorizationXmlElement authz, XmlElement allow
where
  allow = authz.getAChild() and
  isAllOrAnonymousRule(allow, "allow") and
  // In ASP.NET, the first matching rule wins, so a deny rule before the allow takes precedence.
  not exists(XmlElement deny |
    deny = authz.getAChild() and
    isAllOrAnonymousRule(deny, "deny") and
    deny.getIndex() < allow.getIndex()
  ) and
  configuresAuthentication(authz.getFile())
select allow,
  "This authorization rule allows all users, including anonymous users, to access the application, although it configures authentication."
