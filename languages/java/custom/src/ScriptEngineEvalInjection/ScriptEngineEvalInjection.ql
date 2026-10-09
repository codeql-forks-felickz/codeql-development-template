/**
 * @name Code injection via JavaScript ScriptEngine
 * @description Evaluating user-controlled data as script source with a
 *              `javax.script.ScriptEngine` (Nashorn, Rhino or GraalJS) may
 *              lead to arbitrary code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id java/script-engine-code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.Sanitizers
import ScriptEngineEvalInjectionFlow::PathGraph

/**
 * A method that evaluates or compiles its first argument as script source:
 * `javax.script.ScriptEngine.eval` or `javax.script.Compilable.compile`.
 */
class ScriptEvaluationMethod extends Method {
  ScriptEvaluationMethod() {
    this.getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "ScriptEngine") and
    this.hasName("eval")
    or
    this.getDeclaringType().getAnAncestor().hasQualifiedName("javax.script", "Compilable") and
    this.hasName("compile")
  }
}

/** The script source argument of a call to a `ScriptEvaluationMethod`. */
class ScriptEvaluationSink extends DataFlow::ExprNode {
  MethodCall call;

  ScriptEvaluationSink() {
    call.getMethod() instanceof ScriptEvaluationMethod and
    this.getExpr() = call.getArgument(0)
  }

  /** Gets the call that evaluates or compiles this script source. */
  MethodCall getCall() { result = call }
}

module ScriptEngineEvalInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ScriptEvaluationSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SimpleTypeSanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module ScriptEngineEvalInjectionFlow = TaintTracking::Global<ScriptEngineEvalInjectionConfig>;

from ScriptEngineEvalInjectionFlow::PathNode source, ScriptEngineEvalInjectionFlow::PathNode sink
where ScriptEngineEvalInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Script source evaluated by a ScriptEngine depends on a $@.",
  source.getNode(), "user-provided value"
