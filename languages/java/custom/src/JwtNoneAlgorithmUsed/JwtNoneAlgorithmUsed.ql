/**
 * @name JWT signed or verified with the 'none' algorithm
 * @description Signing or verifying a JSON Web Token (JWT) with the 'none' algorithm
 *              means the token carries no signature, so anyone can forge or modify it.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision high
 * @id java/jwt-none-algorithm-used
 * @tags security
 *       external/cwe/cwe-347
 */

import java
import semmle.code.java.dataflow.DataFlow

/** A call to `com.auth0.jwt.algorithms.Algorithm.none()`. */
class Auth0NoneAlgorithm extends MethodCall {
  Auth0NoneAlgorithm() {
    this.getMethod().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm", "none")
  }
}

/** An argument that selects the algorithm used to sign (`JWTCreator.Builder.sign`) or verify (`JWT.require`) a token. */
class Auth0AlgorithmUse extends Expr {
  string use;

  Auth0AlgorithmUse() {
    exists(MethodCall mc | this = mc.getArgument(0) |
      mc.getMethod().hasQualifiedName("com.auth0.jwt", "JWTCreator$Builder", "sign") and
      use = "signed"
      or
      mc.getMethod().hasQualifiedName("com.auth0.jwt", "JWT", "require") and
      use = "verified"
    )
  }

  /** Gets `signed` or `verified`. */
  string getUse() { result = use }
}

module NoneAlgorithmConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof Auth0NoneAlgorithm }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() instanceof Auth0AlgorithmUse }
}

module NoneAlgorithmFlow = DataFlow::Global<NoneAlgorithmConfig>;

from DataFlow::Node source, DataFlow::Node sink, Auth0AlgorithmUse use
where NoneAlgorithmFlow::flow(source, sink) and use = sink.asExpr()
select use, "This JWT is " + use.getUse() + " with the $@, so its signature is never checked.",
  source, "'none' algorithm"
