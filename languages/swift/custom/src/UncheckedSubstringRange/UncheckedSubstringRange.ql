/**
 * @name Unchecked substring range
 * @description Using the result of `NSString.range(of:)` to compute a substring
 *              without checking that the searched text was found can crash the app
 *              or extract the wrong data when the input does not have the expected
 *              format.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id swift/unchecked-substring-range
 * @tags security
 *       correctness
 *       external/cwe/cwe-020
 *       external/cwe/cwe-129
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.ControlFlowGraph

/** A call to `NSString.range(of:)` or one of its overloads. */
class NSStringRangeOfCall extends CallExpr {
  NSStringRangeOfCall() {
    exists(Method m |
      this.getStaticTarget() = m and
      m.getName().matches("range(of:%") and
      m.getEnclosingDecl().asNominalTypeDecl().getABaseTypeDecl*().getName() = "NSString"
    )
  }
}

/** Gets `e` with any optional bindings and force unwraps removed. */
private Expr stripped(Expr e) {
  result = e and
  not result instanceof BindOptionalExpr and
  not result instanceof ForceValueExpr
  or
  result = stripped(e.(BindOptionalExpr).getSubExpr())
  or
  result = stripped(e.(ForceValueExpr).getSubExpr())
}

/** Holds if `ref` reads the `location` or `length` field of an `NSRange`. */
private predicate isNSRangeFieldRead(MemberRefExpr ref) {
  exists(VarDecl field |
    field = ref.getMember() and
    field.getName() = ["location", "length"] and
    field.getEnclosingDecl().asNominalTypeDecl().getName() = ["_NSRange", "NSRange"]
  )
}

/**
 * Holds if the value of `e` is derived (in the same function) from the range
 * returned by `call`, either directly or through its `location`/`length` fields.
 */
private predicate derivedFromRange(NSStringRangeOfCall call, Expr e) {
  TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(e))
  or
  derivedFromRangeField(call, e, _)
}

/**
 * Holds if `e` is derived from the `location` or `length` field of the range
 * returned by `call`.
 */
private predicate derivedFromRangeField(NSStringRangeOfCall call, Expr e, string fieldName) {
  exists(MemberRefExpr ref |
    isRangeFieldOfLookup(call, ref, fieldName) and
    TaintTracking::localTaint(DataFlow::exprNode(ref), DataFlow::exprNode(e))
  )
}

/** Holds if `field` directly reads the given range field from the result of `call`. */
private predicate isRangeFieldOfLookup(NSStringRangeOfCall call, Expr field, string fieldName) {
  exists(MemberRefExpr ref |
    field = ref and
    isNSRangeFieldRead(ref) and
    ref.getMember().(VarDecl).getName() = fieldName and
    TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(stripped(ref.getBase())))
  )
}

/**
 * Holds if `arg` is an argument that is used as a position or range within a
 * string, for example the argument of `NSString.substring(with:)` or of
 * `NSRange(location:length:)`.
 */
private predicate isSubstringBoundArgument(Expr arg) {
  exists(CallExpr c, Function f | c.getStaticTarget() = f |
    (
      f.getEnclosingDecl().asNominalTypeDecl().getABaseTypeDecl*().getName() = "NSString" and
      f.getName() =
        ["substring(with:)", "substring(from:)", "substring(to:)", "replacingCharacters(in:with:)"] and
      arg = c.getArgument(0).getExpr()
      or
      f.(Initializer).getEnclosingDecl().asNominalTypeDecl().getName() = ["_NSRange", "NSRange"] and
      f.getName() = "init(location:length:)" and
      arg = c.getAnArgument().getExpr()
      or
      f.getName() = "NSMakeRange(_:_:)" and
      arg = c.getAnArgument().getExpr()
    )
  )
}

/** Holds if `e` is the `NSNotFound` constant. */
private predicate isNSNotFound(Expr e) {
  e.(DeclRefExpr).getDecl().(VarDecl).getName() = "NSNotFound"
}

/** Holds if `e` is the integer literal `0`. */
private predicate isZero(Expr e) {
  e.(IntegerLiteralExpr).getStringValue() = "0"
}

/**
 * Holds if `check` checks whether the range returned by `call` is present, and
 * `passing` indicates whether a present range makes the check evaluate to true.
 */
private predicate isPresenceCheck(NSStringRangeOfCall call, Expr check, boolean passing) {
  exists(BinaryExpr cmp, Expr value, Expr sentinel |
    check = cmp and
    (
      cmp.getLeftOperand() = value and
      cmp.getRightOperand() = sentinel
      or
      cmp.getRightOperand() = value and
      cmp.getLeftOperand() = sentinel
    ) and
    (
      isRangeFieldOfLookup(call, value, "location") and
      isNSNotFound(sentinel) and
      (
        cmp.getStaticTarget().getName() = "!=(_:_:)" and passing = true
        or
        cmp.getStaticTarget().getName() = "==(_:_:)" and passing = false
      )
      or
      isRangeFieldOfLookup(call, value, "length") and
      isZero(sentinel) and
      (
        cmp.getStaticTarget().getName() = "!=(_:_:)" and passing = true
        or
        cmp.getStaticTarget().getName() = "==(_:_:)" and passing = false
      )
    )
  )
}

/** Holds if a presence check's passing branch dominates this use of the range. */
private predicate isCheckedBeforeUse(NSStringRangeOfCall call, Expr boundArgument) {
  exists(ConditionBlock bb, Expr check, boolean passing |
    check = bb.getLastNode().getNode().asAstNode() and
    isPresenceCheck(call, check, passing) and
    bb.edgeDominates(
      DataFlow::exprNode(boundArgument).getCfgNode().getBasicBlock(),
      any(BooleanSuccessor s | s.getValue() = passing)
    )
  )
}

from NSStringRangeOfCall call
where
  exists(Expr arg |
    derivedFromRange(call, arg) and
    isSubstringBoundArgument(arg) and
    not isCheckedBeforeUse(call, arg)
  )
select call,
  "This search result is used to compute a substring range without checking that the text was found."
