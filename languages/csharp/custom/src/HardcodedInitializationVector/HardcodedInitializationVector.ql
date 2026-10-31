/**
 * @name Hard-coded initialization vector
 * @description A fixed initialization vector makes encryption deterministic and can reveal
 *              relationships between encrypted values.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cs/hardcoded-initialization-vector
 * @tags security
 *       external/cwe/cwe-329
 */

import csharp

/** Holds if `array` is a zero-filled byte array. */
predicate isZeroByteArray(ArrayCreation array) {
  array.getArrayType().getElementType() instanceof ByteType and
  (
    not array.hasInitializer()
    or
    exists(ArrayInitializer initializer |
      initializer = array.getInitializer() and
      initializer.getNumberOfElements() > 0 and
      forall(Expr element |
        element = initializer.getAnElement()
      |
        element instanceof IntLiteral and element.(IntLiteral).getValue() = "0"
      )
    )
  )
}

from AssignExpr assignment, PropertyAccess iv, ArrayCreation array
where
  iv = assignment.getLeftOperand() and
  iv.getTarget().hasName("IV") and
  iv.getQualifier().getType().(RefType).getABaseType*().hasFullyQualifiedName(
    "System.Security.Cryptography",
    "SymmetricAlgorithm"
  ) and
  array = assignment.getRightOperand() and
  isZeroByteArray(array)
select assignment, "Use a fresh cryptographically random initialization vector for each encryption."
