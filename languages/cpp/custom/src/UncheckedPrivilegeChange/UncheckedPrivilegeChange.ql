/**
 * @name Unchecked return value of privilege-changing function
 * @description Ignoring the result of a call that impersonates a client, reverts
 *              impersonation or drops privileges means that, if the call fails, the
 *              program keeps running with an unexpected (possibly more privileged)
 *              security context.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id cpp/unchecked-privilege-change
 * @tags security
 *       external/cwe/cwe-273
 *       external/cwe/cwe-252
 */

import cpp
import semmle.code.cpp.commons.VoidContext
import lib.PrivilegeModels

/** Holds if the result of `call` is discarded. */
predicate resultDiscarded(FunctionCall call) {
  call instanceof ExprInVoidContext
  or
  call.getFullyConverted().getUnspecifiedType() instanceof VoidType
}

from FunctionCall call, PrivilegeChangeFunction f
where
  call.getTarget() = f and
  resultDiscarded(call)
select call, "The return value of $@ is ignored, so a failed privilege change goes undetected.", f,
  f.getName()
