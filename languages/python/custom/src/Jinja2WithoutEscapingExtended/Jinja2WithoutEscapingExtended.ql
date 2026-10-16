/**
 * @name Jinja2 templating with autoescape=False (extended)
 * @description Using jinja2 templates with 'autoescape=False' can
 *              cause a cross-site scripting vulnerability. Extends
 *              `py/jinja2/autoescape-false` to framework helpers that
 *              construct the `jinja2.Environment` on the application's behalf.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id py/jinja2/autoescape-false-extended
 * @tags security
 *       external/cwe/cwe-079
 */

import python
import semmle.python.ApiGraphs

/**
 * Gets a helper that forwards its keyword arguments to `jinja2.Environment`
 * and enables autoescaping unless `autoescape` is explicitly overridden.
 *
 * See https://github.com/aio-libs/aiohttp-jinja2/blob/master/aiohttp_jinja2/__init__.py
 */
private API::Node jinja2EnvironmentWrapper() {
  result = API::moduleImport("aiohttp_jinja2").getMember("setup")
}

from API::CallNode call
where
  call = jinja2EnvironmentWrapper().getACall() and
  call.getKeywordParameter("autoescape")
      .getAValueReachingSink()
      .asExpr()
      .(ImmutableLiteral)
      .booleanValue() = false
select call, "Using jinja2 templates with autoescape=False can potentially allow XSS attacks."
