/**
 * @name Free of a pointer-to-pointer parameter
 * @description Freeing a pointer-to-pointer parameter may release memory not owned by the function.
 * @kind problem
 * @precision medium
 * @problem.severity warning
 * @security-severity 5.3
 * @id cpp/free-of-pointer-parameter
 * @tags security
 *       external/cwe/cwe-590
 */

import cpp

from FunctionCall freeCall, Parameter parameter, VariableAccess argument
where
  freeCall.getTarget().hasGlobalName("free") and
  argument = freeCall.getArgument(0) and
  argument.getTarget() = parameter and
  parameter.getFunction() = freeCall.getEnclosingFunction() and
  exists(PointerType outerPointer, PointerType innerPointer |
    outerPointer = parameter.getUnspecifiedType() and
    innerPointer = outerPointer.getBaseType().getUnspecifiedType()
  )
select freeCall,
  "Freeing this pointer-to-pointer parameter may release caller-owned memory."