/**
 * @name Uncontrolled data appended in place to an OS command
 * @description Reading user-supplied data directly onto the end of a string that
 *              already holds a command, and then executing that string, can make
 *              code vulnerable to command injection.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cpp/custom/command-line-injection-appended-input
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import cpp
import semmle.code.cpp.security.CommandExecution
import semmle.code.cpp.security.FlowSources
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.ir.dataflow.TaintTracking
import AppendedInputFlow::PathGraph

/** A call to a function such as `strlen` that returns the length of a string. */
class StrlenCall extends FunctionCall {
  StrlenCall() {
    this.getTarget().hasGlobalOrStdOrBslName(["strlen", "strnlen", "wcslen"])
    or
    this.getTarget().hasGlobalName(["_mbslen", "_mbslen_l", "_mbstrlen", "_mbstrlen_l"])
  }

  /** Gets the string whose length is computed. */
  Expr getString() { result = this.getArgument(0) }
}

/** Holds if `a` and `b` refer to the same buffer. */
bindingset[a, b]
predicate sameBuffer(Expr a, Expr b) {
  globalValueNumber(a) = globalValueNumber(b)
  or
  exists(Variable v |
    a.(VariableAccess).getTarget() = v and
    b.(VariableAccess).getTarget() = v
  )
}

/**
 * Holds if `ptr` points at the terminating null character of the string in `base`,
 * that is, `ptr` is `base + strlen(base)` or `&base[strlen(base)]`. Data written to
 * `ptr` is appended to the existing contents of `base`, just like `strcat(base, ...)`.
 */
predicate isEndOfString(Expr ptr, Expr base) {
  exists(Expr offset, StrlenCall len |
    (
      exists(PointerAddExpr add | add = ptr.getUnconverted() |
        base = add.getLeftOperand().getUnconverted() and offset = add.getRightOperand()
      )
      or
      exists(ArrayExpr ae | ae = ptr.getUnconverted().(AddressOfExpr).getOperand() |
        base = ae.getArrayBase().getUnconverted() and offset = ae.getArrayOffset()
      )
    ) and
    DataFlow::localExprFlow(len, offset.getUnconverted()) and
    sameBuffer(len.getString().getUnconverted(), base)
  )
}

/**
 * A source of user input that is written directly onto the end of an existing
 * string, for example `recv(sock, cmd + strlen(cmd), ...)`.
 */
class AppendedInputSource extends DataFlow::Node instanceof FlowSource {
  Expr base;

  AppendedInputSource() { isEndOfString(this.asDefiningArgument(), base) }

  /** Gets the buffer whose existing contents the input is appended to. */
  Expr getBase() { result = base }

  /** Gets a description of the kind of user input. */
  string getSourceType() { result = super.getSourceType() }
}

module AppendedInputConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof AppendedInputSource }

  predicate isSink(DataFlow::Node sink) { shellCommand(sink.asIndirectArgument(), _) }

  predicate isBarrier(DataFlow::Node node) {
    node.asExpr().getUnspecifiedType() instanceof IntegralType
    or
    node.asExpr().getUnspecifiedType() instanceof FloatingPointType
  }

  predicate isBarrierOut(DataFlow::Node node) {
    // Prevent duplicates along a call chain, since `shellCommand` includes wrappers
    isSink(node)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module AppendedInputFlow = TaintTracking::Global<AppendedInputConfig>;

from
  AppendedInputFlow::PathNode source, AppendedInputFlow::PathNode sink, Expr command,
  string callChain
where
  AppendedInputFlow::flowPath(source, sink) and
  command = sink.getNode().asIndirectArgument() and
  shellCommand(command, callChain)
select command, source, sink,
  "This argument to an OS command is derived from $@, appended in place to the existing command string in $@, and then passed to "
    + callChain + ".", source,
  "user input (" + source.getNode().(AppendedInputSource).getSourceType() + ")",
  source.getNode().(AppendedInputSource).getBase(),
  source.getNode().(AppendedInputSource).getBase().toString()
