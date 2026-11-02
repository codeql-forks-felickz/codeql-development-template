/**
 * @name Process started without a fully qualified path
 * @description Starting an external program by its bare name (for example `ls` or
 *              `cmd.exe`) makes the operating system resolve it through the `PATH`
 *              search path (and, on Windows, the application and current directories).
 *              An attacker who can place a same-named executable earlier in that search
 *              order can run their own program with the privileges of the application.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.7
 * @precision medium
 * @id cs/untrusted-search-path
 * @tags security
 *       external/cwe/cwe-426
 *       external/cwe/cwe-427
 */

import csharp
import UntrustedSearchPathFlow::PathGraph

/**
 * A string literal that names a program without any directory component, so that it
 * is resolved through the search path when it is started.
 *
 * Names with a file extension other than a Windows executable extension (for example
 * `readme.txt`) are excluded, since they are typically documents opened through a file
 * association rather than programs looked up on the search path.
 */
class BareExecutableNameLiteral extends StringLiteral {
  BareExecutableNameLiteral() {
    exists(string v | v = this.getValue() |
      v.regexpMatch("[A-Za-z0-9_][A-Za-z0-9_.+-]*") and
      (
        not v.regexpMatch(".*\\.[A-Za-z][A-Za-z0-9]*")
        or
        v.regexpMatch("(?i).*\\.(exe|com|bat|cmd)")
      )
    )
  }
}

/** An expression that specifies the program file to start as a new process. */
class ProcessFileNameSink extends DataFlow::ExprNode {
  ProcessFileNameSink() {
    // startInfo.FileName = ... (including object initializers)
    exists(Property p |
      p.getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "ProcessStartInfo") and
      p.hasName("FileName") and
      this.getExpr() = p.getAnAssignedValue()
    )
    or
    // new ProcessStartInfo(fileName, ...) and Process.Start(fileName, ...)
    exists(Call c, Callable target |
      target = c.getTarget() and
      (
        target
            .(InstanceConstructor)
            .getDeclaringType()
            .hasFullyQualifiedName("System.Diagnostics", "ProcessStartInfo")
        or
        target.(Method).isStatic() and
        target.hasName("Start") and
        target.getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "Process")
      ) and
      this.getExpr() = c.getArgumentForName("fileName")
    )
  }
}

module UntrustedSearchPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof BareExecutableNameLiteral }

  predicate isSink(DataFlow::Node sink) { sink instanceof ProcessFileNameSink }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UntrustedSearchPathFlow = DataFlow::Global<UntrustedSearchPathConfig>;

from UntrustedSearchPathFlow::PathNode source, UntrustedSearchPathFlow::PathNode sink
where UntrustedSearchPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This process is started using the bare program name $@, which is resolved through the untrusted search path.",
  source.getNode(), source.getNode().asExpr().(StringLiteral).getValue()
