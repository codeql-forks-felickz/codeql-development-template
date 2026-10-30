/**
 * @name XPath injection from an unresolved ASP.NET Core controller
 * @description Building an XPath expression from a parameter of an ASP.NET Core
 *              controller action is vulnerable to insertion of malicious code by
 *              the user. This query covers controllers whose ASP.NET Core base
 *              type could not be resolved (for example in `build-mode: none`
 *              databases), which `cs/xml/xpath-injection` does not recognize.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cs/xml/xpath-injection-unresolved-controller
 * @tags security
 *       external/cwe/cwe-643
 */

import csharp
import semmle.code.csharp.security.dataflow.XPathInjectionQuery
import UnresolvedAspNetCoreController
import XpathInjection::PathGraph

from XpathInjection::PathNode source, XpathInjection::PathNode sink
where
  XpathInjection::flowPath(source, sink) and
  // Only report flows that `cs/xml/xpath-injection` cannot find on its own.
  source.getNode() instanceof UnresolvedAspNetCoreActionMethodParameter
select sink.getNode(), source, sink, "This XPath expression depends on a $@.", source.getNode(),
  "user-provided value"
