/**
 * @name Dereference through a wider pointer type
 * @description Reading a wider pointer type through a pointer to a smaller local object can read beyond the object's storage.
 * @kind problem
 * @precision medium
 * @problem.severity warning
 * @security-severity 5.3
 * @id cpp/stack-object-type-confusion
 * @tags security
 *       external/cwe/cwe-843
 */

import cpp

from
  CStyleCast cast, PointerDereferenceExpr dereference, LocalVariable pointer, LocalVariable object,
  AssignExpr assignment, AddressOfExpr address, VariableAccess objectAccess, Type targetType
where
  cast.getExpr() = pointer.getAnAccess() and
  pointer.getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() instanceof VoidType and
  assignment.getLValue().(VariableAccess).getTarget() = pointer and
  assignment.getRValue().getAChild*() = address and
  objectAccess = address.getOperand() and
  objectAccess.getTarget() = object and
  object.getFunction() = cast.getEnclosingFunction() and
  pointer.getFunction() = cast.getEnclosingFunction() and
  targetType = cast.getExplicitlyConverted().getUnspecifiedType().(PointerType).getBaseType() and
  targetType.getSize() > object.getUnspecifiedType().getSize() and
  dereference.getOperand() = cast.getExpr() and
  dereference.getEnclosingFunction() = cast.getEnclosingFunction() and
  not exists(AssignExpr write | write.getLValue() = dereference)
select dereference,
  "This dereference reads a larger type through a pointer to a smaller local object."
