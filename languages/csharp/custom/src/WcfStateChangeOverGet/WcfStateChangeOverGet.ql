/**
 * @name WCF service operation changes state over HTTP GET
 * @description A WCF web operation exposed with `[WebGet]` or `[WebInvoke(Method = "GET")]`
 *              that modifies data can be triggered by a cross-site request, for example from an
 *              image tag, using the victim's cookies.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @id cs/web/wcf-state-change-over-get
 * @tags security
 *       external/cwe/cwe-352
 */

import csharp
import AccessControl.AccessControlCoverage

/** Holds if `attr` exposes the operation it is applied to over HTTP `GET`. */
predicate isGetAttribute(Attribute attr) {
  attr.getType().hasFullyQualifiedName("System.ServiceModel.Web", "WebGetAttribute")
  or
  attr.getType().hasFullyQualifiedName("System.ServiceModel.Web", "WebInvokeAttribute") and
  attr.getNamedArgument("Method").getValue().toUpperCase() = "GET"
}

/** Holds if the name of `op` indicates that it creates or modifies data. */
predicate isStateChangingOperation(WcfServiceOperation op) {
  isStateChanging(op)
  or
  op.getName()
      .regexpMatch("(?i)(add|create|insert|place|submit|transfer|pay|purchase|approve|reset).*")
}

from WcfServiceOperation op, Attribute attr
where
  attr = [op.getAContractMethod(), op].getAnAttribute() and
  isGetAttribute(attr) and
  isStateChangingOperation(op)
select op,
  "This service operation changes state but is exposed over HTTP GET by $@, so it can be triggered by a cross-site request.",
  attr, "this attribute"
