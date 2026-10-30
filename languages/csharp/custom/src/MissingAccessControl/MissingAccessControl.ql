/**
 * @name Missing function level access control
 * @description Sensitive actions should have authorization checks to prevent them from being used by malicious actors.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cs/web/missing-function-level-access-control
 * @tags security
 *       external/cwe/cwe-285
 *       external/cwe/cwe-284
 *       external/cwe/cwe-862
 */

import csharp
import semmle.code.csharp.security.auth.MissingFunctionLevelAccessControlQuery
import WebMethodActions

private ValueOrRefType getWebMethodAuthBaseType(ValueOrRefType t) {
  result = t.getABaseType().getUnboundDeclaration()
}

private predicate isMvcAuthorizeAttribute(Attribute attr) {
  attr.getType().getABaseType*().hasFullyQualifiedName("System.Web.Mvc", "AuthorizeAttribute")
}

private predicate isOtherAuthAttribute(Attribute attr) {
  attr.getType().getABaseType*().getName().toLowerCase().matches("%auth%") and
  not isMvcAuthorizeAttribute(attr)
}

private predicate hasMvcAuthorizeAttribute(ActionMethod m) {
  exists(Attribute attr |
    isMvcAuthorizeAttribute(attr) and
    (
      attr = m.getOverridee*().getAnAttribute()
      or
      attr = getWebMethodAuthBaseType*(m.getDeclaringType()).getAnAttribute()
    )
  )
}

private predicate hasOtherAuthAttribute(ActionMethod m) {
  exists(Attribute attr |
    isOtherAuthAttribute(attr) and
    (
      attr = m.getOverridee*().getAnAttribute()
      or
      attr = getWebMethodAuthBaseType*(m.getDeclaringType()).getAnAttribute()
    )
  )
}

private predicate mvcAuthorizeDoesNotProtectWebMethod(ActionMethod m) {
  m instanceof WebMethodActionMethod and
  needsAuth(m) and
  hasMvcAuthorizeAttribute(m) and
  not hasOtherAuthAttribute(m) and
  not hasAuthViaCode(m) and
  not hasAuthViaXml(m) and
  exists(m.getBody().getAChildStmt())
}

from Method m
where missingAuth(m) or mvcAuthorizeDoesNotProtectWebMethod(m)
select m, "This action is missing an authorization check."
