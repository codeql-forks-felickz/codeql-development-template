/**
 * @name Copy overruns structure member array
 * @description Copying more bytes into an array member of a structure than the
 *              member can hold overwrites the members that follow it, even
 *              when the write stays inside the enclosing structure.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id cpp/custom/copy-overruns-struct-member
 * @tags security
 *       external/cwe/cwe-121
 *       external/cwe/cwe-122
 *       external/cwe/cwe-787
 *       external/cwe/cwe-805
 */

import cpp
import semmle.code.cpp.commons.Buffer
import semmle.code.cpp.models.interfaces.ArrayFunction

/**
 * Holds if `fc` writes exactly `n` bytes (a compile-time constant) to the
 * buffer passed as its `dest` argument.
 */
predicate fixedSizeByteWrite(FunctionCall fc, Expr dest, int n) {
  exists(ArrayFunction f, int destParam, int countParam, Type base |
    f = fc.getTarget() and
    f.hasArrayOutput(destParam) and
    f.hasArrayWithVariableSize(destParam, countParam) and
    dest = fc.getArgument(destParam) and
    n = fc.getArgument(countParam).getValue().toInt() and
    base = f.getParameter(destParam).getUnspecifiedType().(PointerType).getBaseType() and
    (base instanceof VoidType or base.getSize() = 1)
  )
}

from FunctionCall fc, FieldAccess fa, Field f, ArrayType t, int n
where
  fixedSizeByteWrite(fc, fa, n) and
  f = fa.getTarget() and
  t = f.getUnspecifiedType() and
  // Arrays of size 0 or 1, or without a size, may be variable-sized trailing members.
  not memberMayBeVarSize(_, f) and
  n > t.getSize()
select fc,
  "This call writes " + n + " bytes into the member $@, which is only " + t.getSize() +
    " bytes, overwriting the members that follow it.", f, f.getName()
