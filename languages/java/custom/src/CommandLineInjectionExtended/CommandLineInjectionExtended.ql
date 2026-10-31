/**
 * @name Uncontrolled command line (extended)
 * @description Using externally controlled strings in a command line is vulnerable to malicious
 *              changes in the strings. This variant of `java/command-line-injection` additionally
 *              treats fields read in a custom `readObject` deserialization method as untrusted,
 *              and tracks Kotlin `toString()` calls on Android `Editable` text.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/command-line-injection-extended
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess
import CommandLineInjectionExtensions
import CommandLineInjectionExtendedFlow::PathGraph

from
  CommandLineInjectionExtendedFlow::PathNode source,
  CommandLineInjectionExtendedFlow::PathNode sink, Expr execArg
where
  CommandLineInjectionExtendedFlow::flowPath(source, sink) and
  argumentToExec(execArg, sink.getNode()) and
  // Results already reported by `java/command-line-injection` are not repeated.
  not InputToArgumentToExecFlow::flowTo(sink.getNode())
select execArg, source, sink, "This command line depends on a $@.", source.getNode(),
  sourceDescription(source.getNode())
