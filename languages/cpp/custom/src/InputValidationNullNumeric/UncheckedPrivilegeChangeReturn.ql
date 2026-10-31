/**
 * @name Unchecked return value of privilege-changing function
 * @description Ignoring the result of a call that impersonates, reverts or
 *              drops privileges (such as `ImpersonateSelf` or `setuid`) means
 *              the program keeps running in an unexpected security context
 *              when the call fails.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.4
 * @precision high
 * @id cpp/unchecked-privilege-change-return
 * @tags security
 *       external/cwe/cwe-252
 *       external/cwe/cwe-273
 */

import cpp

/** A function that changes the security context of the current thread or process. */
class PrivilegeChangeFunction extends Function {
  PrivilegeChangeFunction() {
    this.hasGlobalName([
        // Windows impersonation and token APIs
        "ImpersonateSelf", "ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient",
        "ImpersonateAnonymousToken", "ImpersonateDdeClientWindow", "RpcImpersonateClient",
        "CoImpersonateClient", "RevertToSelf", "RpcRevertToSelf", "CoRevertToSelf",
        "SetThreadToken",
        // POSIX credential APIs
        "setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid", "setresuid", "setresgid",
        "setgroups", "initgroups", "setfsuid", "setfsgid"
      ])
  }
}

from FunctionCall call, PrivilegeChangeFunction f
where
  call.getTarget() = f and
  (
    call instanceof ExprInVoidContext
    or
    call.getFullyConverted().(Conversion).getUnspecifiedType() instanceof VoidType
  )
select call,
  "The return value of $@ is not checked, so a failure leaves the program in the wrong security context.",
  f, f.getName()
