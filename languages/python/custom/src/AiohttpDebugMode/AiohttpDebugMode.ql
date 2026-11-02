/**
 * @name aiohttp application created in debug mode
 * @description Creating an aiohttp application with debug mode enabled may expose stack traces
 *              and other internal details of unhandled exceptions to remote users.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision high
 * @id py/aiohttp-debug
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-215
 *       external/cwe/cwe-489
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from API::CallNode call
where
  call = API::moduleImport("aiohttp").getMember("web").getMember("Application").getACall() and
  call.getKeywordParameter("debug")
      .getAValueReachingSink()
      .asExpr()
      .(ImmutableLiteral)
      .booleanValue() = true and
  not exists(KeyValuePair item |
    item = call.getArgByName("handler_args").asExpr().(Dict).getAnItem() and
    item.getKey().(StringLiteral).getText() = "debug" and
    item.getValue().(ImmutableLiteral).booleanValue() = false
  )
select call,
  "An aiohttp application appears to be created in debug mode. This may expose stack traces and other internal details to remote users."
