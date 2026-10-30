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

/** Gets the first whitespace-delimited program name in shell command `cmd`. */
bindingset[cmd]
string getProgramName(string cmd) { result = cmd.regexpCapture("\\s*([^\\s]+).*", 1) }

/**
 * A shell command literal whose first token is resolved through the search path.
 */
class UnqualifiedShellCommandLiteral extends StringLiteral {
  UnqualifiedShellCommandLiteral() {
    exists(string prog | prog = getProgramName(this.getValue()) |
      prog.regexpMatch("[A-Za-z0-9_][A-Za-z0-9_.+-]*")
    )
  }
}

/** A direct executable literal with no directory component or arguments. */
class UnqualifiedExecutableLiteral extends StringLiteral {
  UnqualifiedExecutableLiteral() {
    this.getValue().regexpMatch("[A-Za-z0-9_][A-Za-z0-9_.+-]*")
  }
}

/**
 * A call to a function that runs a command through a shell.
 */
class ShellCommandCall extends FunctionCall {
  ShellCommandCall() {
    this.getTarget().hasGlobalOrStdName(["system", "_wsystem", "popen", "_popen", "_wpopen"])
  }
}

/** A call to a PATH-searching exec or spawn variant. */
class DirectExecutableCall extends FunctionCall {
  DirectExecutableCall() {
    this.getTarget()
        .hasGlobalOrStdName([
            "execlp", "execvp", "execvpe", "_execlp", "_execlpe", "_execvp", "_execvpe",
            "_wexeclp", "_wexeclpe", "_wexecvp", "_wexecvpe", "_spawnlp", "_spawnlpe",
            "_spawnvp", "_spawnvpe", "_wspawnlp", "_wspawnlpe", "_wspawnvp", "_wspawnvpe"
          ])
  }

  /** Gets the argument holding the executable name. */
  Expr getExecutableArgument() {
    if this.getTarget().getName().matches("%spawn%")
    then result = this.getArgument(1)
    else result = this.getArgument(0)
  }
}

bindingset[program]
predicate isShellBuiltin(string program, ShellCommandCall call) {
  (
    call.getTarget().hasGlobalOrStdName(["system", "popen"]) and
    program = ["cd", "exit", "export", "set", "unset", "echo", "test", "true", "false", "read",
      "umask", "wait", "exec", "eval"]
  )
  or
  (
    call.getTarget().hasGlobalOrStdName(["_wsystem", "_popen", "_wpopen"]) and
    program.toLowerCase() =
      ["cd", "dir", "echo", "cls", "pause", "copy", "del", "type", "set", "start", "ver", "exit",
        "mkdir"]
  )
}

newtype TUntrustedSearchPathState =
  TShellCommandState(StringLiteral literal) or
  TDirectExecutableState(StringLiteral literal)

class UntrustedSearchPathState extends TUntrustedSearchPathState {
  string toString() {
    this = TShellCommandState(_) and result = "shell command"
    or
    this = TDirectExecutableState(_) and result = "direct executable"
  }
}

module UntrustedSearchPathConfig implements DataFlow::StateConfigSig {
  class FlowState = UntrustedSearchPathState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    exists(UnqualifiedShellCommandLiteral literal |
      source.asIndirectExpr() = literal and
      state = TShellCommandState(literal)
    )
    or
    exists(UnqualifiedExecutableLiteral literal |
      source.asIndirectExpr() = literal and
      state = TDirectExecutableState(literal)
    )
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    (
      exists(ShellCommandCall call, StringLiteral literal, string program |
        sink.asIndirectExpr() = call.getArgument(0) and
        state = TShellCommandState(literal) and
        program = getProgramName(literal.getValue()) and
        not isShellBuiltin(program, call)
      )
    )
    or
    (
      exists(StringLiteral literal | state = TDirectExecutableState(literal)) and
      sink.asIndirectExpr() = any(DirectExecutableCall call).getExecutableArgument()
    )
  }

  predicate isBarrierIn(DataFlow::Node node, FlowState state) { isSource(node, state) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedSearchPathFlow = DataFlow::GlobalWithState<UntrustedSearchPathConfig>;

string getReportedProgram(UntrustedSearchPathState state) {
  exists(StringLiteral literal |
    state = TShellCommandState(literal) and
    result = getProgramName(literal.getValue())
  )
  or
  exists(StringLiteral literal |
    state = TDirectExecutableState(literal) and
    result = literal.getValue()
  )
}

from UntrustedSearchPathFlow::PathNode source, UntrustedSearchPathFlow::PathNode sink
where UntrustedSearchPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command runs $@ without a fully qualified path, so it is resolved using the untrusted search path.",
  source.getNode(), getReportedProgram(source.getState())
