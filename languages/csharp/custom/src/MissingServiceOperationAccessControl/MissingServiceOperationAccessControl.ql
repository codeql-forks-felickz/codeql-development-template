/**
 * @name Missing access control on WCF service operation
 * @description A publicly callable WCF service operation that modifies a resource selected by
 *              a caller-supplied ID, without authenticating the caller or checking that they
 *              are allowed to modify it, lets anyone modify arbitrary resources.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id cs/web/missing-service-operation-access-control
 * @tags security
 *       external/cwe/cwe-285
 *       external/cwe/cwe-639
 *       external/cwe/cwe-862
 */

import csharp
import semmle.code.csharp.security.auth.MissingFunctionLevelAccessControlQuery as MissingAccessControl
import AccessControl.AccessControlCoverage

from WcfServiceOperation m
where
  isStateChanging(m) and
  hasIdParameter(m) and
  not checksCurrentUser(m) and
  not MissingAccessControl::hasAuthViaXml(m) and
  not exists(Attribute a |
    a = getAnApplicableAttribute(m) and
    (
      isRestrictingAuthorizationAttribute(a) or
      a.getType().getName().matches("Authorize%")
    )
  ) and
  exists(m.getBody().getAChildStmt())
select m,
  "This service operation modifies the resource of the provided ID without checking that the caller is authorized to do so."
