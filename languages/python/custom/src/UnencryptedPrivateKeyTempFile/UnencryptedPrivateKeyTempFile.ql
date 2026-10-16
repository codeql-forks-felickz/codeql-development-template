/**
 * @name Unencrypted private key written to a shared temporary directory
 * @description Writing an unencrypted private key to a predictable path in a world-writable
 *              temporary directory (such as `/tmp/ca.key`) with default permissions lets
 *              other local users read the key or pre-create the file or a symlink to it.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/unencrypted-private-key-temp-file
 * @tags security
 *       external/cwe/cwe-522
 *       external/cwe/cwe-312
 *       external/cwe/cwe-377
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * A call that serializes a private key without encryption, such as
 * `key.private_bytes(..., encryption_algorithm=serialization.NoEncryption())` or
 * `OpenSSL.crypto.dump_privatekey(FILETYPE_PEM, key)` without a cipher.
 */
class UnencryptedPrivateKeySerialization extends DataFlow::CallCfgNode {
  UnencryptedPrivateKeySerialization() {
    exists(API::CallNode noEncryption |
      noEncryption =
        API::moduleImport("cryptography")
            .getMember("hazmat")
            .getMember("primitives")
            .getMember("serialization")
            .getMember("NoEncryption")
            .getACall() and
      this.(DataFlow::MethodCallNode).getMethodName() = "private_bytes" and
      noEncryption.flowsTo([this.getArg(2), this.getArgByName("encryption_algorithm")])
    )
    or
    this = API::moduleImport("OpenSSL").getMember("crypto").getMember("dump_privatekey").getACall() and
    not exists([this.getArg(2), this.getArgByName("cipher")])
  }
}

/** A predictable location in a shared, world-writable temporary directory. */
class SharedTempPath extends DataFlow::Node {
  SharedTempPath() {
    this.asExpr().(StringLiteral).getText().regexpMatch("/(tmp|var/tmp|dev/shm)(/.*)?")
    or
    this = API::moduleImport("tempfile").getMember("gettempdir").getACall()
  }
}

module SharedTempPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SharedTempPath }

  predicate isSink(DataFlow::Node sink) { sink = any(FileSystemWriteAccess w).getAPathArgument() }
}

module SharedTempPathFlow = TaintTracking::Global<SharedTempPathConfig>;

module UnencryptedPrivateKeyTempFileConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UnencryptedPrivateKeySerialization }

  predicate isSink(DataFlow::Node sink) {
    exists(FileSystemWriteAccess write |
      sink = write.getADataNode() and
      SharedTempPathFlow::flowTo(write.getAPathArgument())
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UnencryptedPrivateKeyTempFileFlow =
  TaintTracking::Global<UnencryptedPrivateKeyTempFileConfig>;

import UnencryptedPrivateKeyTempFileFlow::PathGraph

from
  UnencryptedPrivateKeyTempFileFlow::PathNode source,
  UnencryptedPrivateKeyTempFileFlow::PathNode sink
where UnencryptedPrivateKeyTempFileFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This writes an $@ to a predictable path in a shared temporary directory.", source.getNode(),
  "unencrypted private key"
