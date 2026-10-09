/**
 * @name Uncontrolled command line (extended)
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command. This variant of
 *              `py/command-line-injection` additionally tracks taint through captured
 *              variables defined by tuple unpacking and through `urllib.parse.parse_qsl`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @sub-severity high
 * @precision high
 * @id py/custom/command-line-injection-extended
 * @tags correctness
 *       security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import CommandInjectionExtensions
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command line depends on a $@.", source.getNode(),
  "user-provided value"
