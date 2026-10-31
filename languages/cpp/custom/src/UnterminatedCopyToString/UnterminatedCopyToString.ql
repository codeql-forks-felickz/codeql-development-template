/**
 * @name String use after a possibly unterminated copy
 * @description Using an uninitialized character array as a string after a near-full memcpy may read past its end.
 * @kind problem
 * @precision medium
 * @problem.severity warning
 * @security-severity 5.3
 * @id cpp/unterminated-copy-to-string
 * @tags security
 *       external/cwe/cwe-170
 */

import cpp
import semmle.code.cpp.commons.NullTermination

from
  FunctionCall copy, LocalVariable destination, ArrayType destinationType, FunctionCall stringUse,
  int argumentIndex, VariableAccess copyDestinationAccess, VariableAccess stringDestinationAccess,
  int copyLength
where
  copy.getTarget().hasGlobalName(["memcpy", "memmove"]) and
  copy.getArgument(0).getAChild*() = copyDestinationAccess and
  destination = copyDestinationAccess.getTarget() and
  not destination.hasInitializer() and
  destinationType = destination.getUnspecifiedType() and
  destinationType.getBaseType().getUnspecifiedType() instanceof CharType and
  copyLength = copy.getArgument(2).getFullyConverted().getValue().toInt() and
  copyLength >= destinationType.getArraySize() - 1 and
  stringUse.getTarget().hasGlobalName(["printf", "fprintf", "sprintf", "snprintf"]) and
  stringUse.getArgument(argumentIndex).getAChild*() = stringDestinationAccess and
  stringDestinationAccess.getTarget() = destination and
  variableMustBeNullTerminated(stringDestinationAccess) and
  not exists(AssignExpr terminator, ArrayExpr element |
    terminator.getLValue() = element and
    element.getArrayBase().getAChild*().(VariableAccess).getTarget() = destination and
    terminator.getRValue().getFullyConverted().getValue().toInt() = 0
  ) and
  not exists(FunctionCall clear |
    clear.getTarget().hasGlobalName("memset") and
    clear.getArgument(0).getAChild*().(VariableAccess).getTarget() = destination and
    clear.getArgument(1).getFullyConverted().getValue().toInt() = 0
  )
select stringUse,
  "This string use may read past a character array whose copied contents are not explicitly terminated."
