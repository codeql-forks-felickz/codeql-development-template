/**
 * @name Information exposure through an error message or stack trace (extended)
 * @description Propagating error messages or stack trace information to an external user can
 *              unintentionally reveal implementation details that are useful to an attacker
 *              for developing a subsequent exploit. This variant of `js/stack-trace-exposure`
 *              additionally tracks Express error-handler, callback and promise rejection
 *              errors, error messages, and the `errorhandler` middleware.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.4
 * @precision medium
 * @id js/stack-trace-exposure-extended
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-497
 */

import javascript
import StackTraceExposureExtensions
import StackTraceExposureExtendedFlow::PathGraph

from StackTraceExposureExtendedFlow::PathNode source, StackTraceExposureExtendedFlow::PathNode sink
where StackTraceExposureExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This information exposed to the user depends on $@.",
  source.getNode(), "error message or stack trace information"
