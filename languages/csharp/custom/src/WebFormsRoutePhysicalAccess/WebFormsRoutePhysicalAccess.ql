/**
 * @name Web Forms route bypasses physical URL authorization
 * @description A Web Forms route registered with checkPhysicalUrlAccess set to false bypasses
 *              authorization checks for the physical page mapped to the route.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id cs/web/webforms-route-physical-url-access-disabled
 * @tags security
 *       external/cwe/cwe-862
 */

import csharp

from MethodCall mapPageRoute
where
  mapPageRoute
      .getTarget()
      .hasFullyQualifiedName("System.Web.Routing", "RouteCollection", "MapPageRoute") and
  mapPageRoute.getArgumentForName("checkPhysicalUrlAccess").(BoolLiteral).getBoolValue() = false
select mapPageRoute, "This Web Forms route disables physical URL authorization checks."
