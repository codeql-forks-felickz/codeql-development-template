/**
 * @name Improper control of generation of code via CodeDomProvider
 * @description Compiling externally controlled source text with
 *              `CodeDomProvider.CompileAssemblyFromSource` can allow an attacker
 *              to execute malicious code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id cs/code-injection-codedom-provider
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-096
 */

import csharp
import semmle.code.csharp.security.dataflow.CodeInjectionQuery
private import semmle.code.csharp.frameworks.system.codedom.Compiler
import CodeInjection::PathGraph

/**
 * A `sources` argument to a call to `CodeDomProvider.CompileAssemblyFromSource`.
 *
 * `CodeDomProvider` (the base class of `CSharpCodeProvider` and `VBCodeProvider`)
 * does not implement `ICodeCompiler`, so these calls are not covered by the
 * standard `CompileAssemblyFromSourceSink`. Because `sources` is a `params`
 * parameter, each expanded argument is a separate sink.
 */
class CodeDomProviderCompileAssemblyFromSourceSink extends Sink {
  CodeDomProviderCompileAssemblyFromSourceSink() {
    exists(Method m, MethodCall mc |
      m.getDeclaringType().(SystemCodeDomCompilerClass).hasName("CodeDomProvider") and
      m.hasName("CompileAssemblyFromSource") and
      mc = m.getAnOverrider*().getACall() and
      this.getExpr() = mc.getArgumentForName("sources")
    )
  }
}

from CodeInjection::PathNode source, CodeInjection::PathNode sink
where
  CodeInjection::flowPath(source, sink) and
  // Only report the sinks added by this query, the remaining sinks are
  // already reported by the standard `cs/code-injection` query.
  sink.getNode() instanceof CodeDomProviderCompileAssemblyFromSourceSink
select sink.getNode(), source, sink, "This code compilation depends on a $@.", source.getNode(),
  "user-provided value"
