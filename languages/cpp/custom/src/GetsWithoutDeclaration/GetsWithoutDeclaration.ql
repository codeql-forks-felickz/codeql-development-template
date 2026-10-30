/**
 * @name Use of gets without a prototype
 * @description The `gets` function cannot limit the amount of data it reads and
 *              always risks overflowing its buffer. Calls are still dangerous
 *              when `gets` is implicitly declared, for example because the C
 *              library headers no longer declare it.
 * @kind problem
 * @problem.severity error
 * @security-severity 10.0
 * @precision very-high
 * @id cpp/custom/gets-without-declaration
 * @tags security
 *       external/cwe/cwe-242
 *       external/cwe/cwe-120
 *       external/cwe/cwe-121
 *       external/cwe/cwe-676
 */

import cpp

from FunctionCall call, Function target
where
  call.getTarget() = target and
  target.hasGlobalName("gets") and
  call.getNumberOfArguments() = 1 and
  // Calls to a `gets` declared with one parameter are reported by the standard
  // `cpp/dangerous-function-overflow` query.
  not target.getNumberOfParameters() = 1
select call, "'gets' does not guard against buffer overflow."
