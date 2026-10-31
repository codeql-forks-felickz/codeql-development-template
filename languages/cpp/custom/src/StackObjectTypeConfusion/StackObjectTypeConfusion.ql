/**
 * @name Dereference of a wider type through an expired stack object
 * @description Reading a wider pointer type after the pointed-to stack object leaves scope can read out of bounds.
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
  CStyleCast cast, PointerDereferenceExpr dereference, LocalVariable pointer,
  LocalVariable object, AssignExpr assignment, AddressOfExpr address,
  VariableAccess objectAccess, DeclStmt declaration, BlockStmt objectScope,
  Type targetType
where
  cast.getExpr() = pointer.getAnAccess() and
  pointer.getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() instanceof VoidType and
  assignment.getLValue().(VariableAccess).getTarget() = pointer and
  assignment.getRValue().getAChild*() = address and
  objectAccess = address.getOperand() and
  objectAccess.getTarget() = object and
  declaration.getADeclaration() = object and
  objectScope = address.getEnclosingBlock() and
  objectScope.getEnclosingBlock() = cast.getEnclosingBlock() and
  object.getFunction() = cast.getEnclosingFunction() and
  pointer.getFunction() = cast.getEnclosingFunction() and
  targetType = cast.getExplicitlyConverted().getUnspecifiedType().(PointerType).getBaseType() and
  targetType.getSize() > object.getUnspecifiedType().getSize() and
  dereference.getOperand() = cast and
  dereference.getEnclosingFunction() = cast.getEnclosingFunction() and
  not exists(AssignExpr write | write.getLValue() = dereference)
select dereference,
  "This dereference reads a larger type through a pointer to a stack object whose scope has ended."