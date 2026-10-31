/**
 * @name Credential buffer is not cleared before release
 * @description A password passed to a Windows logon API remains in a local or
 *              freed buffer because the buffer is not securely cleared.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id cpp/credential-memory-not-cleared
 * @tags security
 *       external/cwe/cwe-226
 *       external/cwe/cwe-244
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow

class LogonCall extends FunctionCall {
  LogonCall() {
    this.getTarget().hasGlobalName(["LogonUserA", "LogonUserW", "LogonUserExA", "LogonUserExW"])
  }

  Expr getPassword() { result = this.getArgument(2) }
}

class SecureClearCall extends FunctionCall {
  SecureClearCall() {
    this.getTarget()
        .hasGlobalName(["SecureZeroMemory", "RtlSecureZeroMemory", "memset_s", "explicit_bzero"])
  }
}

predicate clearsPassword(LogonCall logon) {
  exists(SecureClearCall clear |
    clear.getEnclosingFunction() = logon.getEnclosingFunction() and
    clear.getLocation().getStartLine() > logon.getLocation().getStartLine() and
    DataFlow::localExprFlow(logon.getPassword().getUnconverted(),
      clear.getArgument(0).getUnconverted())
  )
}

predicate isStackPassword(LogonCall logon) {
  exists(VariableAccess access |
    logon.getPassword().getUnconverted() = access and
    access.getEnclosingFunction() = logon.getEnclosingFunction() and
    access.getTarget().getUnspecifiedType() instanceof ArrayType
  )
}

class HeapReleaseCall extends FunctionCall {
  HeapReleaseCall() { this.getTarget().hasGlobalOrStdName("free") }
}

predicate releasesPassword(LogonCall logon, HeapReleaseCall release) {
  logon.getEnclosingFunction() = release.getEnclosingFunction() and
  logon.getLocation().getStartLine() < release.getLocation().getStartLine() and
  DataFlow::localExprFlow(logon.getPassword().getUnconverted(),
    release.getArgument(0).getUnconverted())
}

from LogonCall logon, Expr problemLocation
where
  not clearsPassword(logon) and
  (
    isStackPassword(logon) and problemLocation = logon
    or
    exists(HeapReleaseCall release | releasesPassword(logon, release) and problemLocation = release)
  )
select problemLocation, "This password buffer is not securely cleared before it is released."
