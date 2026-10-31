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
  exists(MemberRefExpr ref |
    isNSRangeFieldRead(ref) and
    TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(stripped(ref.getBase()))) and
    TaintTracking::localTaint(DataFlow::exprNode(ref), DataFlow::exprNode(e))
  )
}

/**
 * Holds if `arg` is an argument that is used as a position or range within a
 * string, for example the argument of `NSString.substring(with:)` or of
 * `NSRange(location:length:)`.
 */
private predicate isSubstringBoundArgument(Expr arg) {
  exists(CallExpr c, Function f | c.getStaticTarget() = f and arg = c.getAnArgument().getExpr() |
    f.getEnclosingDecl().asNominalTypeDecl().getABaseTypeDecl*().getName() = "NSString" and
    f.getName() =
      ["substring(with:)", "substring(from:)", "substring(to:)", "replacingCharacters(in:with:)"]
    or
    f.(Initializer).getEnclosingDecl().asNominalTypeDecl().getName() = ["_NSRange", "NSRange"] and
    f.getName() = "init(location:length:)"
    or
    f.getName() = "NSMakeRange(_:_:)"
  )
}

/** Holds if `call`'s result is compared with something (for example `NSNotFound`). */
private predicate isChecked(NSStringRangeOfCall call) {
  exists(BinaryExpr cmp |
    cmp.getStaticTarget().getName() =
      ["==(_:_:)", "!=(_:_:)", "<(_:_:)", "<=(_:_:)", ">(_:_:)", ">=(_:_:)"] and
    derivedFromRange(call, cmp.getAnOperand())
  )
}

from NSStringRangeOfCall call
where
  exists(Expr arg | derivedFromRange(call, arg) and isSubstringBoundArgument(arg)) and
  not isChecked(call)
select call,
  "This search result is used to compute a substring range without checking that the text was found."
