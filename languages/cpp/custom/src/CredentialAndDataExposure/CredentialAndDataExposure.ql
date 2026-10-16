/**
 * @name Plaintext password read from a file
 * @description Reading a password from a file and using it for authentication without
 *              decrypting it first means the credential is stored in plaintext on disk,
 *              where anyone with read access to the file can obtain it.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cpp/credential-and-data-exposure
 * @tags security
 *       external/cwe/cwe-256
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking

/** A call that opens a file and returns (or outputs) a handle to it. */
class FileOpenCall extends FunctionCall {
  FileOpenCall() {
    this.getTarget()
        .hasGlobalOrStdName([
            "fopen", "_wfopen", "freopen", "_wfreopen", "fopen_s", "_wfopen_s", "CreateFileA",
            "CreateFileW", "CreateFile"
          ])
  }

  /** Holds if `e` is an expression that refers to the file handle opened by this call. */
  predicate refersToHandle(Expr e) {
    DataFlow::localExprFlow(this, e)
    or
    // `fopen_s(&pFile, ...)` returns the handle through its first parameter.
    this.getTarget().hasGlobalOrStdName(["fopen_s", "_wfopen_s"]) and
    exists(Variable v |
      this.getArgument(0).(AddressOfExpr).getOperand() = v.getAnAccess() and
      e = v.getAnAccess()
    )
  }
}

/** A call that reads data from a file handle into a buffer. */
class FileReadCall extends FunctionCall {
  int streamArg;

  FileReadCall() {
    this.getTarget().hasGlobalOrStdName(["fgets", "fgetws"]) and streamArg = 2
    or
    this.getTarget().hasGlobalOrStdName("fread") and streamArg = 3
    or
    this.getTarget().hasGlobalOrStdName(["fscanf", "fwscanf", "fscanf_s", "fwscanf_s"]) and
    streamArg = 0
    or
    this.getTarget().hasGlobalName("ReadFile") and streamArg = 0
  }

  /** Gets an argument of this call that receives data read from the file. */
  Expr getABufferArgument() {
    this.getTarget().hasGlobalOrStdName(["fgets", "fgetws", "fread"]) and
    result = this.getArgument(0)
    or
    this.getTarget().hasGlobalOrStdName(["fscanf", "fwscanf", "fscanf_s", "fwscanf_s"]) and
    result = this.getArgument(any(int i | i >= 2))
    or
    this.getTarget().hasGlobalName("ReadFile") and result = this.getArgument(1)
  }

  /** Holds if this call reads from a handle obtained by opening a file. */
  predicate readsFromFile() {
    exists(FileOpenCall open | open.refersToHandle(this.getArgument(streamArg)))
  }
}

/**
 * Gets the index of the password parameter of an authentication function `f`.
 */
int passwordParameterIndex(Function f) {
  f.hasGlobalName([
      "LogonUserA", "LogonUserW", "LogonUser", "LogonUserExA", "LogonUserExW", "LogonUserEx",
      "CreateProcessWithLogonW"
    ]) and
  result = 2
  or
  f.hasGlobalName("mysql_real_connect") and result = 3
  or
  f.hasGlobalName([
      "ldap_simple_bind", "ldap_simple_bind_s", "ldap_simple_bind_sA", "ldap_simple_bind_sW"
    ]) and
  result = 2
}

/**
 * A call that decrypts a buffer in place, so its contents after the call are no longer
 * the plaintext that was stored on disk.
 */
class InPlaceDecryptCall extends FunctionCall {
  int bufArg;

  InPlaceDecryptCall() {
    this.getTarget().hasGlobalName("CryptDecrypt") and bufArg = 4
    or
    this.getTarget().hasGlobalName("CryptUnprotectMemory") and bufArg = 0
  }

  /** Gets the buffer that is decrypted in place. */
  Expr getBuffer() { result = this.getArgument(bufArg).getUnconverted() }
}

module PlaintextStoredPasswordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(FileReadCall read |
      read.readsFromFile() and
      source.asDefiningArgument() = read.getABufferArgument().getUnconverted()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
      sink.asIndirectExpr() = call.getArgument(passwordParameterIndex(call.getTarget()))
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(InPlaceDecryptCall decrypt | node.asDefiningArgument() = decrypt.getBuffer())
  }
}

module PlaintextStoredPasswordFlow = TaintTracking::Global<PlaintextStoredPasswordConfig>;

import PlaintextStoredPasswordFlow::PathGraph

from PlaintextStoredPasswordFlow::PathNode source, PlaintextStoredPasswordFlow::PathNode sink
where PlaintextStoredPasswordFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This password is read in plaintext from a file at $@ and used for authentication without being decrypted.",
  source.getNode(), "this location"
