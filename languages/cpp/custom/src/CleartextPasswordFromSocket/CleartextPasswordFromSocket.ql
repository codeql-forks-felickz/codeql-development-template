/**
 * @name Password received from a socket is used without decryption
 * @description A password read directly from a raw socket is used for
 *              authentication without first being decrypted.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision low
 * @id cpp/cleartext-password-from-socket
 * @tags security
 *       external/cwe/cwe-319
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking

class SocketReceiveCall extends FunctionCall {
  SocketReceiveCall() { this.getTarget().hasGlobalOrStdName(["recv", "recvfrom"]) }

  Expr getBuffer() { result = this.getArgument(1) }
}

class LogonCall extends FunctionCall {
  LogonCall() {
    this.getTarget().hasGlobalName(["LogonUserA", "LogonUserW", "LogonUserExA", "LogonUserExW"])
  }

  Expr getPassword() { result = this.getArgument(2) }
}

class InPlaceDecryptCall extends FunctionCall {
  int bufferArgument;

  InPlaceDecryptCall() {
    this.getTarget().hasGlobalName("CryptDecrypt") and bufferArgument = 4
    or
    this.getTarget().hasGlobalName("CryptUnprotectMemory") and bufferArgument = 0
  }

  Expr getBuffer() { result = this.getArgument(bufferArgument).getUnconverted() }
}

module CleartextSocketPasswordConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(SocketReceiveCall receive |
      source.asDefiningArgument() = receive.getBuffer().getUnconverted()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(LogonCall logon | sink.asIndirectExpr() = logon.getPassword())
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(InPlaceDecryptCall decrypt | node.asIndirectExpr() = decrypt.getBuffer())
  }
}

module CleartextSocketPasswordFlow = TaintTracking::Global<CleartextSocketPasswordConfig>;

import CleartextSocketPasswordFlow::PathGraph

from CleartextSocketPasswordFlow::PathNode source, CleartextSocketPasswordFlow::PathNode sink
where CleartextSocketPasswordFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This password is received from a raw socket at $@ and used for authentication without being decrypted.",
  source.getNode(), "this location"
