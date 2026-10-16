/**
 * @name JWT verified with a key taken from the token header
 * @description Verifying a JSON Web Token (JWT) with the public key embedded in its own
 *              attacker-controlled 'jwk' header lets an attacker sign forged tokens with
 *              a key pair of their choice.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/jwt-header-embedded-key-trusted
 * @tags security
 *       external/cwe/cwe-347
 */

import java
import semmle.code.java.dataflow.TaintTracking

/** A call `x.get*(k)` where `k` is the constant `name`. */
private predicate headerRead(MethodCall mc, string name) {
  mc.getMethod().getName().matches("get%") and
  mc.getNumArgument() = 1 and
  mc.getArgument(0).(CompileTimeConstantExpr).getStringValue() = name
}

/**
 * A read of the token-supplied JSON Web Key, either `header.get*("jwk")` on an object
 * that is also read for its `alg` (i.e. a decoded JWT header), or Nimbus `Header.getJWK()`.
 */
class EmbeddedJwkRead extends MethodCall {
  EmbeddedJwkRead() {
    headerRead(this, "jwk") and
    exists(Variable v, MethodCall algRead |
      this.getQualifier() = v.getAnAccess() and
      headerRead(algRead, "alg") and
      algRead.getQualifier() = v.getAnAccess()
    )
    or
    this.getMethod().hasName("getJWK") and
    this.getMethod().getDeclaringType().getASupertype*().getPackage().hasName("com.nimbusds.jose")
  }
}

/** The construction of a Nimbus JWS signature verifier. */
class JwsVerifierCreation extends ClassInstanceExpr {
  JwsVerifierCreation() {
    this.getConstructedType().getASupertype*().hasQualifiedName("com.nimbusds.jose", "JWSVerifier")
  }
}

module EmbeddedJwkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof EmbeddedJwkRead }

  predicate isSink(DataFlow::Node sink) {
    sink.asExpr() = any(JwsVerifierCreation c).getAnArgument()
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Key parsing and conversion, e.g. `RSAKey.parse(json)`, `jwk.toRSAPublicKey()` and
    // `jsonObject.toString()`.
    exists(MethodCall mc, string pkg |
      pkg = mc.getMethod().getDeclaringType().getPackage().getName() and
      (pkg.matches("com.nimbusds.jose%") or pkg = "org.json") and
      node2.asExpr() = mc
    |
      node1.asExpr() = mc.getQualifier() or node1.asExpr() = mc.getAnArgument()
    )
  }
}

module EmbeddedJwkFlow = TaintTracking::Global<EmbeddedJwkConfig>;

from DataFlow::Node source, DataFlow::Node sink, JwsVerifierCreation verifier
where EmbeddedJwkFlow::flow(source, sink) and sink.asExpr() = verifier.getAnArgument()
select verifier, "This verifier checks the JWT signature with a $@, which the attacker controls.",
  source, "key taken from the token's own header"
