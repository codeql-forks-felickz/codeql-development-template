/**
 * @name Code injection from local user input
 * @description Interpreting command-line arguments or standard input as code allows anyone who
 *              controls the process input to perform arbitrary code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id rb/code-injection-local-source
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 */

private import codeql.ruby.AST
private import codeql.ruby.ApiGraphs
private import codeql.ruby.frameworks.core.Kernel
private import codeql.ruby.security.CodeInjectionQuery
import DataFlow::DeduplicatePathGraph<CodeInjectionFlow::PathNode, CodeInjectionFlow::PathGraph>

/**
 * A read of local user input from the command line (`ARGV`) or from standard input,
 * considered as a source for code injection.
 */
class LocalInputSource extends Source {
  string kind;

  LocalInputSource() {
    this = API::getTopLevelMember("ARGV").asSource() and
    kind = "command-line argument"
    or
    this =
      API::getTopLevelMember(["STDIN", "ARGF"])
          .getAMethodCall(["gets", "read", "readline", "readlines"]) and
    kind = "value from stdin"
    or
    exists(DataFlow::Node dollarStdin |
      dollarStdin.asExpr().getExpr().(GlobalVariableReadAccess).getVariable().getName() = "$stdin" and
      this = dollarStdin.getALocalSource().getAMethodCall(["gets", "read", "readline", "readlines"])
    ) and
    kind = "value from stdin"
    or
    this.(Kernel::KernelMethodCall).getMethodName() = ["gets", "readline", "readlines"] and
    kind = "value from stdin"
  }

  /** Gets a description of this source. */
  string getKind() { result = kind }
}

from PathNode source, PathNode sink
where
  CodeInjectionFlow::flowPath(source.getAnOriginalPathNode(), sink.getAnOriginalPathNode()) and
  source.getNode() instanceof LocalInputSource
select sink.getNode(), source, sink, "This code execution depends on a $@.", source.getNode(),
  source.getNode().(LocalInputSource).getKind()
