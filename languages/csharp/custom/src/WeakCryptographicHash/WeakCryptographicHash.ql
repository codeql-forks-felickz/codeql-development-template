/**
 * @name Weak or unsalted hash used for a secret
 * @description Weak hashes and unsalted password hashes can expose credentials and other secrets.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id cs/weak-cryptographic-hash
 * @tags security
 *       external/cwe/cwe-328
 *       external/cwe/cwe-759
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking

/** A weak MD5 hash, or a hash of a directly supplied password. */
class WeakHashCall extends DataFlow::ExprNode {
  WeakHashCall() {
    exists(MethodCall mc | mc = this.getExpr() |
      mc.getTarget().hasName(["ComputeHash", "HashData"]) and
      (
        mc.getTarget().getDeclaringType().hasFullyQualifiedName(
          "System.Security.Cryptography",
          "MD5"
        )
        or
        mc.getQualifier().getType().(RefType).getABaseType*().hasFullyQualifiedName(
          "System.Security.Cryptography",
          "MD5"
        )
        or
        exists(VariableAccess password |
          password.getTarget().getName().regexpMatch("(?i).*(password|passwd|passphrase).*") and
          (
            mc.getAnArgument() = password
            or
            exists(MethodCall encode |
              mc.getAnArgument() = encode and
              encode.getTarget().hasName("GetBytes") and
              encode.getAnArgument() = password
            )
          )
        )
      )
    )
  }
}

/** A value assigned to a password, credential, secret or token hash. */
class SecretHashSink extends DataFlow::ExprNode {
  SecretHashSink() {
    exists(Expr e | e = this.getExpr() |
      exists(Assignable a |
        a.getName().regexpMatch("(?i).*(password|passwd|credential|secret|token).*") and
        e = a.getAnAssignedValue()
      )
      or
      exists(Parameter p |
        p.getName().regexpMatch("(?i).*(password|passwd|credential|secret|token).*") and
        e = p.getAnAssignedArgument()
      )
    )
  }
}

module WeakHashConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof WeakHashCall }

  predicate isSink(DataFlow::Node sink) { sink instanceof SecretHashSink }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof SecretHashSink }
}

module WeakHashFlow = TaintTracking::Global<WeakHashConfig>;

import WeakHashFlow::PathGraph

from WeakHashFlow::PathNode source, WeakHashFlow::PathNode sink
where WeakHashFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This security-sensitive hash uses a weak algorithm or hashes a password without a salt."
