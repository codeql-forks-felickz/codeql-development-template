/**
 * @name Server-side request forgery through an external fetch command
 * @description Passing a user-controlled URL to an external `curl` or `wget` process lets an
 *              attacker make the server fetch arbitrary resources, including internal services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/ssrf-command-line-fetch
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.ExternalProcess
import semmle.code.java.security.RequestForgery

/** Holds if `s` names a URL-fetching program, optionally with a path. */
bindingset[s]
private predicate isFetchProgram(string s) { s.regexpMatch("(?i)(.*[/\\\\])?(curl|wget)(\\.exe)?") }

/** Holds if `s` is the start of a command line that runs a URL-fetching program. */
bindingset[s]
private predicate isFetchCommandLinePrefix(string s) {
  s.regexpMatch("(?is)\\s*(\\S*[/\\\\])?(curl|wget)(\\.exe)?(\\s.*)?")
}

/**
 * Holds if `e` is the element at position `i` of the command executed through `exec`.
 * A command given as a single string is its own element at position 0.
 */
private predicate commandElement(ArgumentToExec exec, Expr e, int i) {
  exec.getType() instanceof TypeString and e = exec and i = 0
  or
  exists(Call c, int first |
    exec = c.getArgument(first) and
    exec.(Argument).isNthVararg(0) and
    e = c.getArgument(first + i)
  )
  or
  exists(ArrayInit ai |
    DataFlow::localExprFlow([ai.(Expr), ai.getParent().(ArrayCreationExpr)], exec) and
    e = ai.getInit(i)
  )
  or
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName("java.util", ["Arrays", "List"]) and
    mc.getMethod().hasName(["asList", "of"]) and
    DataFlow::localExprFlow(mc, exec) and
    e = mc.getArgument(i)
  )
}

/** Gets the leftmost operand of the string concatenation `e`, or `e` itself. */
private Expr leftmostOperand(Expr e) {
  if e instanceof AddExpr
  then result = leftmostOperand(e.(AddExpr).getLeftOperand())
  else result = e
}

/** Gets the rightmost operand of the string concatenation `e`, or `e` itself. */
private Expr rightmostOperand(Expr e) {
  if e instanceof AddExpr
  then result = rightmostOperand(e.(AddExpr).getRightOperand())
  else result = e
}

/**
 * A command element that is a whole command line (for example the script passed to `sh -c`,
 * or the single string passed to `Runtime.exec`) starting with `curl` or `wget`.
 */
private class FetchCommandLine extends Expr {
  FetchCommandLine() {
    commandElement(_, this, _) and
    isFetchCommandLinePrefix(leftmostOperand(this).(CompileTimeConstantExpr).getStringValue())
  }

  private Expr getAnAddOperand() {
    result = this.(AddExpr).getAnOperand()
    or
    result = this.getAnAddOperand().(AddExpr).getAnOperand()
  }

  /** Gets an operand of this concatenation, other than its first one. */
  Expr getAnAppendedOperand() {
    result = this.getAnAddOperand() and
    not result instanceof AddExpr and
    not result = leftmostOperand(this)
  }
}

/**
 * Holds if `op` is appended to the command line `cl` right after a constant whose final
 * whitespace-separated token fixes the host, for example `curl -s https://example.com/`.
 */
private predicate hostFixedInCommandLine(FetchCommandLine cl, Expr op) {
  op = cl.getAnAppendedOperand() and
  exists(AddExpr parent, string token |
    op = parent.getRightOperand() and
    token =
      rightmostOperand(parent.getLeftOperand())
          .(CompileTimeConstantExpr)
          .getStringValue()
          .regexpCapture("(?s).*?(\\S*)", 1) and
    token.regexpMatch("(?s).*([?#]|[^?#:/\\\\][/\\\\]).*")
  )
}

/** An argument to an external `curl` or `wget` process that selects what is fetched. */
class FetchCommandSink extends DataFlow::Node {
  FetchCommandSink() {
    exists(ArgumentToExec exec, Expr first, int i |
      commandElement(exec, first, 0) and
      isFetchProgram(first.(CompileTimeConstantExpr).getStringValue()) and
      commandElement(exec, this.asExpr(), i) and
      i > 0
    )
    or
    this.asExpr() instanceof FetchCommandLine
  }
}

module CommandLineFetchConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof FetchCommandSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof RequestForgerySanitizer and
    // Inside a command line, a slash in the program path (as in `/usr/bin/curl `) does not
    // restrict the host, so only keep prefix sanitizers that fix the host of the URL token.
    not exists(FetchCommandLine cl |
      node.asExpr() = cl.getAnAppendedOperand() and
      node.asExpr() = any(HostnameSanitizingPrefix p).getAnAppendedExpression() and
      not hostFixedInCommandLine(cl, node.asExpr())
    )
    or
    hostFixedInCommandLine(_, node.asExpr())
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    any(RequestForgeryAdditionalTaintStep r).propagatesTaint(pred, succ)
  }
}

module CommandLineFetchFlow = TaintTracking::Global<CommandLineFetchConfig>;

import CommandLineFetchFlow::PathGraph

from CommandLineFetchFlow::PathNode source, CommandLineFetchFlow::PathNode sink
where CommandLineFetchFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential server-side request forgery: an external fetch command uses a URL that depends on a $@.",
  source.getNode(), "user-provided value"
