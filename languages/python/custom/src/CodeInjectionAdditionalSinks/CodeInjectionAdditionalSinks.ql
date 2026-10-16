/**
 * @name Code injection via additional code-evaluating APIs
 * @description Passing user-controlled text to a library API that evaluates it as Python code
 *              allows a malicious user to execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id py/custom/code-injection-additional-sinks
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.security.dataflow.CodeInjectionQuery
import CodeInjectionFlow::PathGraph

/**
 * A call to Pillow's `PIL.ImageMath.eval` or `PIL.ImageMath.unsafe_eval`, which evaluate the
 * `expression` argument with Python's `eval`. The restricted environment used by `eval` has been
 * escaped in several Pillow releases (for example CVE-2022-22817 and CVE-2023-50447), and
 * `unsafe_eval` makes no attempt at restriction.
 */
class PillowImageMathEval extends CodeExecution::Range, API::CallNode {
  PillowImageMathEval() {
    this =
      API::moduleImport("PIL").getMember("ImageMath").getMember(["eval", "unsafe_eval"]).getACall()
  }

  override DataFlow::Node getCode() { result = this.getParameter(0, "expression").asSink() }
}

from CodeInjectionFlow::PathNode source, CodeInjectionFlow::PathNode sink
where
  CodeInjectionFlow::flowPath(source, sink) and
  // Only report sinks added by this query, the rest are reported by `py/code-injection`.
  sink.getNode() = any(PillowImageMathEval e).getCode()
select sink.getNode(), source, sink, "This code execution depends on a $@.", source.getNode(),
  "user-provided value"
