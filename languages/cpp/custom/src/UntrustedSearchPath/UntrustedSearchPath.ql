/**
 * @name Command executed without a fully qualified path
 * @description Running an external program by its bare name (for example `ls` or
 *              `cmd.exe`) makes the operating system resolve it through the `PATH`
 *              search path (or the current directory on Windows). An attacker who can
 *              influence that search path can cause a malicious program to run with
 *              the privileges of the application.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision medium
 * @id cpp/untrusted-search-path
 * @tags security
 *       external/cwe/cwe-426
 *       external/cwe/cwe-427
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import UntrustedSearchPathFlow::PathGraph

/**
 * Gets the program name of the command string `cmd`, that is, the first
 * whitespace-delimited token after any leading whitespace.
 */
bindingset[cmd]
string getProgramName(string cmd) { result = cmd.regexpCapture("\\s*([^\\s]+).*", 1) }

/**
 * A string literal whose program name is resolved through the search path
 * because it contains no directory component (for example `"ls -la"` or
 * `"cmd.exe /c dir"`).
 */
class UnqualifiedCommandLiteral extends StringLiteral {
  UnqualifiedCommandLiteral() {
    exists(string prog | prog = getProgramName(this.getValue()) |
      prog.regexpMatch("[A-Za-z0-9_][A-Za-z0-9_.+-]*")
    )
  }
}

/**
 * A call to a function that runs a command and resolves its program name using
 * the search path: either through a command interpreter (`system`, `popen`, ...)
 * or through a `PATH`-searching `exec` variant.
 */
class SearchPathCommandCall extends FunctionCall {
  SearchPathCommandCall() {
    this.getTarget()
        .hasGlobalOrStdName([
            "system", "_wsystem", "popen", "_popen", "_wpopen", "execlp", "execvp", "execvpe",
            "_execlp", "_execlpe", "_execvp", "_execvpe", "_wexeclp", "_wexeclpe", "_wexecvp",
            "_wexecvpe", "_spawnlp", "_spawnlpe", "_spawnvp", "_spawnvpe", "_wspawnlp",
            "_wspawnlpe", "_wspawnvp", "_wspawnvpe"
          ])
  }

  /** Gets the argument holding the command or program name. */
  Expr getCommandArgument() {
    if this.getTarget().getName().matches("%spawn%")
    then result = this.getArgument(1)
    else result = this.getArgument(0)
  }
}

module UntrustedSearchPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asIndirectExpr() instanceof UnqualifiedCommandLiteral
  }

  predicate isSink(DataFlow::Node sink) {
    sink.asIndirectExpr() = any(SearchPathCommandCall call).getCommandArgument()
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedSearchPathFlow = DataFlow::Global<UntrustedSearchPathConfig>;

from UntrustedSearchPathFlow::PathNode source, UntrustedSearchPathFlow::PathNode sink
where UntrustedSearchPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command runs $@ without a fully qualified path, so it is resolved using the untrusted search path.",
  source.getNode(), getProgramName(source.getNode().asIndirectExpr().getValue())
