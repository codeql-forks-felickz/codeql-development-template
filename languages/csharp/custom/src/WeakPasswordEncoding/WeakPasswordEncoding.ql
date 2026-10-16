/**
 * @name Stored password protected only by Base64 encoding
 * @description Base64 is an encoding, not encryption. A password that is read from a file,
 *              the registry or a constant and only Base64-decoded before use can be trivially
 *              recovered by anyone who can read the stored value.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cs/weak-password-encoding
 * @tags security
 *       external/cwe/cwe-261
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking

/** Holds if `name` looks like it holds a password. */
bindingset[name]
predicate isPasswordName(string name) {
  name.toLowerCase().regexpMatch(".*(password|passwd|passphrase).*|pwd")
}

/** A read of persisted data: a file, the Windows registry, or a hard-coded string. */
class StoredValue extends DataFlow::ExprNode {
  StoredValue() {
    exists(MethodCall mc | mc = this.getExpr() |
      mc.getTarget()
          .getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName("System.IO", "TextReader") and
      mc.getTarget().getName().matches(["ReadLine%", "ReadToEnd%"])
      or
      mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.IO", "File") and
      mc.getTarget().getName().matches(["ReadAllText%", "ReadAllLines%", "ReadLines%"])
      or
      mc.getTarget()
          .getDeclaringType()
          .hasFullyQualifiedName("Microsoft.Win32", ["Registry", "RegistryKey"]) and
      mc.getTarget().hasName("GetValue")
    )
  }
}

/** Holds if `e` is a hard-coded string, such as a literal or a constant field. */
predicate isHardcodedString(Expr e) {
  exists(StringLiteral l | DataFlow::localExprFlow(l, e))
  or
  e.(FieldAccess).getTarget().getInitializer() instanceof StringLiteral and
  (
    e.(FieldAccess).getTarget().isConst() or
    e.(FieldAccess).getTarget().isReadOnly()
  )
}

/** A call that decodes Base64 data. */
class Base64Decode extends MethodCall {
  Base64Decode() {
    this.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Convert") and
    this.getTarget().hasName(["FromBase64String", "FromBase64CharArray"])
  }
}

module StoredToBase64Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StoredValue }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(Base64Decode d).getArgument(0) }
}

module StoredToBase64Flow = TaintTracking::Global<StoredToBase64Config>;

/** A Base64 decoding of a stored value. */
class StoredBase64Decode extends DataFlow::ExprNode {
  StoredBase64Decode() {
    exists(Base64Decode d | d = this.getExpr() |
      isHardcodedString(d.getArgument(0))
      or
      StoredToBase64Flow::flowToExpr(d.getArgument(0))
    )
  }
}

/** A value used as a password. */
class PasswordSink extends DataFlow::ExprNode {
  PasswordSink() {
    exists(Expr e | e = this.getExpr() |
      exists(Parameter p | isPasswordName(p.getName()) and e = p.getAnAssignedArgument())
      or
      exists(Property p | isPasswordName(p.getName()) and e = p.getAnAssignedValue())
    )
  }
}

/** A call that decrypts or unprotects data, after which the value is no longer just encoded. */
class DecryptionBarrier extends DataFlow::ExprNode {
  DecryptionBarrier() {
    exists(Call c | c = this.getExpr() |
      c.getTarget().getDeclaringType().getNamespace().getFullName() = "System.Security.Cryptography"
      or
      c.getTarget().getName().regexpMatch("(?i).*(decrypt|unprotect|decipher).*")
    )
  }
}

module WeakPasswordEncodingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StoredBase64Decode }

  predicate isSink(DataFlow::Node sink) { sink instanceof PasswordSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof DecryptionBarrier }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof PasswordSink }
}

module WeakPasswordEncodingFlow = TaintTracking::Global<WeakPasswordEncodingConfig>;

import WeakPasswordEncodingFlow::PathGraph

from WeakPasswordEncodingFlow::PathNode source, WeakPasswordEncodingFlow::PathNode sink
where WeakPasswordEncodingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This password is only protected by a $@ of stored data, which is trivially reversible.",
  source.getNode(), "Base64 decoding"
