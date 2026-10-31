/**
 * @name State-changing action routed from a GET request
 * @description Routing a GET request to a controller action that creates, updates or
 *              deletes data bypasses Rails' CSRF protection, which only verifies
 *              tokens for unsafe HTTP methods.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id rb/state-changing-get-route
 * @tags security
 *       external/cwe/cwe-352
 */

import codeql.ruby.AST
import codeql.ruby.frameworks.ActionDispatch

from ActionDispatch::Routing::Route route, string action
where
  route.getHttpMethod() = "get" and
  action = route.getAction() and
  action = ["create", "update", "destroy", "delete"]
select route,
  "This route maps GET requests to the state-changing action '" + route.getController() + "#" +
    action + "', which is not protected by Rails' CSRF verification."
