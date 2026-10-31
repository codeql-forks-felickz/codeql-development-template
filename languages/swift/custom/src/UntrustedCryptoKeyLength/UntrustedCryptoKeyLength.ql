/**
 * @name Fixed crypto key length may exceed the key buffer
 * @description Passing a caller-supplied key buffer to CommonCrypto with a fixed key length
 *              can read beyond the end of the buffer.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id swift/untrusted-crypto-key-length
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-823
 */

import swift
import codeql.swift.controlflow.BasicBlocks
import codeql.swift.controlflow.CfgNodes
import codeql.swift.controlflow.ControlFlowGraph

private predicate isCallerSuppliedKey(Expr dataExpr) {
  exists(DeclRefExpr ref, ParamDecl param |
    dataExpr = ref and
    ref.getDecl() = param and
    param.getType().getUnderlyingType().getName() = ["Data", "NSData"]
  )
  or
  exists(
    DeclRefExpr ref, VarDecl local, ApplyExpr conversion, DeclRefExpr inputRef, ParamDecl param
  |
    dataExpr = ref and
    ref.getDecl() = local and
    local.getType().getUnderlyingType().getName() = "Data" and
    conversion = local.getParentInitializer() and
    conversion.getQualifier() = inputRef and
    inputRef.getDecl() = param and
    param.getType().getUnderlyingType().getName() = "String"
  )
}

private predicate isFixedAes128Length(Expr length) {
  exists(DeclRefExpr ref, VarDecl lengthVar, ApplyExpr initializer, DeclRefExpr constant |
    length = ref and
    ref.getDecl() = lengthVar and
    initializer = lengthVar.getParentInitializer() and
    initializer.getAnArgument().getExpr() = constant and
    constant.getDecl().(VarDecl).getName() = "kCCKeySizeAES128"
  )
  or
  length.(DeclRefExpr).getDecl().(VarDecl).getName() = "kCCKeySizeAES128"
}

private predicate isKeyPointerForData(Expr keyPointer, Expr dataExpr) {
  exists(DeclRefExpr keyRef, ClosureExpr closure, ApplyExpr withUnsafeBytes |
    keyPointer = keyRef and
    keyRef.getDecl() = closure.getParam(0) and
    keyRef.getEnclosingCallable() = closure and
    withUnsafeBytes.getStaticTarget().getName() = "withUnsafeBytes(_:)" and
    withUnsafeBytes.getQualifier() = dataExpr and
    withUnsafeBytes.getAnArgument().getExpr() = closure
  )
  or
  exists(MemberRefExpr bytes, ExplicitCastExpr cast |
    keyPointer = bytes and
    bytes.getMember().(VarDecl).getName() = "bytes" and
    bytes.getBase() = cast and
    cast.getType().getUnderlyingType().getName() = "NSData" and
    cast.getSubExpr() = dataExpr
  )
}

private predicate validatesKeyLength(Expr cond, Expr dataExpr, boolean branch) {
  exists(BinaryExpr cmp, MemberRefExpr countRef, Expr bound |
    cond = cmp and
    countRef = cmp.getLeftOperand() and
    countRef.getMember().(VarDecl).getName() = "count" and
    exists(DeclRefExpr checkedDataRef, DeclRefExpr guardedDataRef |
      dataExpr = checkedDataRef and
      countRef.getBase() = guardedDataRef and
      checkedDataRef.getDecl() = guardedDataRef.getDecl()
    ) and
    bound = cmp.getRightOperand() and
    (
      cmp.getStaticTarget().getShortName() = [">=", ">", "=="] and branch = true
      or
      cmp.getStaticTarget().getShortName() = ["<", "<="] and branch = false
    ) and
    (
      isFixedAes128Length(bound)
      or
      bound instanceof IntegerLiteralExpr and bound.toString() = "16"
    )
  )
}

private predicate hasKeyLengthGuard(CallExpr call, Expr dataExpr) {
  exists(ConditionBlock cb, ExprCfgNode condNode, Expr cond, ExprCfgNode callNode, boolean branch |
    validatesKeyLength(cond, dataExpr, branch) and
    condNode.getExpr() = cond and
    cb.getLastNode() = condNode and
    callNode.getExpr() = call and
    cb.edgeDominates(callNode.getBasicBlock(), any(BooleanSuccessor s | s.getValue() = branch))
  )
}

from CallExpr call, Expr dataExpr
where
  call.getStaticTarget().(Function).getShortName() = "CCCrypt" and
  isFixedAes128Length(call.getArgument(4).getExpr()) and
  isCallerSuppliedKey(dataExpr) and
  isKeyPointerForData(call.getArgument(3).getExpr(), dataExpr) and
  not hasKeyLengthGuard(call, dataExpr)
select call, "This caller-supplied key buffer may be shorter than the fixed AES-128 key length."
