/**
 * @name Use of a fast hash function for password hashing
 * @description Hashing a password with a fast message digest such as MD5, SHA-1 or
 *              SHA-256, with or without a salt, allows efficient brute-force and
 *              rainbow-table recovery of the password.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/weak-password-hashing
 * @tags security
 *       external/cwe/cwe-916
 *       external/cwe/cwe-759
 *       external/cwe/cwe-328
 */

import java
import semmle.code.java.dataflow.TaintTracking
import PasswordStorage

/** An argument to `MessageDigest.digest` or `MessageDigest.update`. */
class MessageDigestInput extends Expr {
  MessageDigestInput() {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
      mc.getMethod().hasName(["digest", "update"]) and
      this = mc.getArgument(0)
    )
  }
}

module WeakPasswordHashingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof PasswordExpr }

  predicate isSink(DataFlow::Node node) { node.asExpr() instanceof MessageDigestInput }

  // Report each flow from the password access closest to the sink only.
  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module WeakPasswordHashingFlow = TaintTracking::Global<WeakPasswordHashingConfig>;

import WeakPasswordHashingFlow::PathGraph

from WeakPasswordHashingFlow::PathNode source, WeakPasswordHashingFlow::PathNode sink
where WeakPasswordHashingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This $@ is hashed with a fast message digest that is not suitable for password storage. Use a password hashing function such as Argon2, scrypt, bcrypt or PBKDF2 instead.",
  source.getNode(), "password"
