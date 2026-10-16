/**
 * @name Code injection via user-controlled Python module write
 * @description Writing user-controlled text into a Python source file allows a malicious user
 *              to persist arbitrary code that runs when the module is imported or reloaded.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision medium
 * @id py/custom/code-injection-python-module-write
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CodeInjectionCustomizations::CodeInjection as CodeInjection

/**
 * Holds if `node` evaluates to a path naming a Python source file (`*.py` or `*.pyw`), for
 * example `"main.py"`, `os.path.join(dirname, "playground/main.py")`, `base + "/main.py"`,
 * `f"{base}/main.py"` or `pathlib.Path(base) / "main.py"`.
 */
predicate namesPythonSourceFile(DataFlow::Node node) {
  node.asExpr().(StringLiteral).getText().regexpMatch("(?s).*\\.pyw?")
  or
  exists(Fstring f | f = node.asExpr() |
    f.getValue(max(int i | exists(f.getValue(i))))
        .(StringLiteral)
        .getText()
        .regexpMatch("(?s).*\\.pyw?")
  )
  or
  exists(BinaryExpr b |
    b = node.asExpr() and
    (b.getOp() instanceof Add or b.getOp() instanceof Div)
  |
    namesPythonSourceFile(DataFlow::exprNode(b.getRight()))
  )
  or
  exists(DataFlow::CallCfgNode call | call = node |
    call = API::moduleImport("os").getMember("path").getMember("join").getACall() and
    namesPythonSourceFile(call.getArg(max(int i | exists(call.getArg(i)))))
    or
    call =
      API::moduleImport("pathlib")
          .getMember(["Path", "PurePath", "PosixPath", "WindowsPath"])
          .getACall() and
    namesPythonSourceFile(call.getArg(max(int i | exists(call.getArg(i)))))
  )
  or
  exists(DataFlow::Node pred |
    namesPythonSourceFile(pred) and
    DataFlow::localFlowStep(pred, node)
  )
}

/** A node that is written to a Python source file. */
class PythonModuleWriteSink extends DataFlow::Node {
  PythonModuleWriteSink() {
    exists(FileSystemWriteAccess write |
      this = write.getADataNode() and
      namesPythonSourceFile(write.getAPathArgument())
    )
  }
}

private module PythonModuleWriteConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CodeInjection::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof PythonModuleWriteSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CodeInjection::Sanitizer }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // Generated modules are often assembled from lists of lines, for example
    // `"\n".join(header_lines + user_lines)`, so propagate list contents through `+`.
    exists(BinaryExpr add | add.getOp() instanceof Add | node.asExpr() = add.getASubExpression()) and
    c.isSingleton(any(DataFlow::ListElementContent lc))
  }
}

module PythonModuleWriteFlow = TaintTracking::Global<PythonModuleWriteConfig>;

import PythonModuleWriteFlow::PathGraph

from PythonModuleWriteFlow::PathNode source, PythonModuleWriteFlow::PathNode sink
where PythonModuleWriteFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This Python source file content depends on a $@ and may be executed when the module is loaded.",
  source.getNode(), "user-provided value"
