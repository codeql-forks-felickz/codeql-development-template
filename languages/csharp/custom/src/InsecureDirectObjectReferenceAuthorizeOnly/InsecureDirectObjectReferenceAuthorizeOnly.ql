/**
 * @name Insecure direct object reference protected only by authentication
 * @description A state-changing action that selects a resource by a user-supplied ID and is
 *              protected only by a plain `[Authorize]` attribute, without checking that the
 *              current user owns the resource or has a privileged role, lets any
 *              authenticated user modify or delete other users' resources.
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id cs/web/insecure-direct-object-reference-authorize-only
 * @tags security
 *       external/cwe/cwe-639
 *       external/cwe/cwe-862
 */

import csharp
import AccessControl.AccessControlCoverage

from ActionMethod m
where
  isStateChanging(m) and
  hasIdParameter(m) and
  isProtectedOnlyByAuthentication(m) and
  not checksCurrentUser(m) and
  exists(m.getBody().getAChildStmt())
select m,
  "This action only requires an authenticated user and does not check that the current user owns, or is authorized to modify, the resource of the provided ID."
