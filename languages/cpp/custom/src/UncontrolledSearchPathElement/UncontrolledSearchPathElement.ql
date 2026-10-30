/**
 * @name Uncontrolled search path element
 * @description Setting a search-path environment variable such as `PATH` or
 *              `LD_LIBRARY_PATH` from user-controlled data lets an attacker choose
 *              where later unqualified programs or libraries are loaded from.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id cpp/uncontrolled-search-path-element
 * @tags security
 *       external/cwe/cwe-427
 */

import cpp
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.ir.dataflow.TaintTracking
import UncontrolledSearchPathElementFlow::PathGraph

/** Holds if `name` is an environment variable that controls a search path. */
bindingset[name]
predicate isSearchPathVariable(string name) {
  name.toUpperCase() =
    [
      "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH",
      "DYLD_INSERT_LIBRARIES"
    ]
}

/** A call to `putenv` and its variants, which take a single `NAME=value` string. */
class PutenvCall extends FunctionCall {
  PutenvCall() { this.getTarget().hasGlobalName(["putenv", "_putenv", "_wputenv"]) }
}

/**
 * A call to a function that sets an environment variable from a separate name
 * and value, where the name is a search-path variable.
 */
class SearchPathSetEnvCall extends FunctionCall {
  SearchPathSetEnvCall() {
    this.getTarget()
        .hasGlobalName([
            "setenv", "_putenv_s", "_wputenv_s", "SetEnvironmentVariable",
            "SetEnvironmentVariableA", "SetEnvironmentVariableW"
          ]) and
    isSearchPathVariable(this.getArgument(0).getValue())
  }
}

/** Gets the variable name assigned by the `NAME=value` string literal `lit`. */
string getAssignedName(StringLiteral lit) {
  result = lit.getValue().regexpCapture("([A-Za-z_][A-Za-z0-9_]*)=.*", 1)
}

/** Tracks `NAME=` string literals to the argument of a `putenv` call. */
module EnvAssignmentLiteralConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { exists(getAssignedName(source.asIndirectExpr())) }

  predicate isSink(DataFlow::Node sink) {
    sink.asIndirectExpr() = any(PutenvCall call).getArgument(0)
  }
}

module EnvAssignmentLiteralFlow = DataFlow::Global<EnvAssignmentLiteralConfig>;

/**
 * Holds if the `putenv` argument `arg` may assign a search-path variable: either a
 * `NAME=` prefix for such a variable reaches it, or no `NAME=` prefix is known (so
 * the variable name may itself be attacker-controlled).
 */
predicate mayAssignSearchPath(Expr arg) {
  exists(DataFlow::Node sink | sink.asIndirectExpr() = arg |
    exists(DataFlow::Node lit |
      EnvAssignmentLiteralFlow::flow(lit, sink) and
      isSearchPathVariable(getAssignedName(lit.asIndirectExpr()))
    )
    or
    not EnvAssignmentLiteralFlow::flowTo(sink)
  )
}

module UncontrolledSearchPathElementConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(PutenvCall call |
      sink.asIndirectExpr() = call.getArgument(0) and
      mayAssignSearchPath(call.getArgument(0))
    )
    or
    sink.asIndirectExpr() = any(SearchPathSetEnvCall call).getArgument(1)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UncontrolledSearchPathElementFlow =
  TaintTracking::Global<UncontrolledSearchPathElementConfig>;

from
  UncontrolledSearchPathElementFlow::PathNode source,
  UncontrolledSearchPathElementFlow::PathNode sink
where UncontrolledSearchPathElementFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This search path environment variable is set from $@, so an attacker can control where programs or libraries are loaded from.",
  source.getNode(), source.getNode().(FlowSource).getSourceType()
