/**
 * @name BCrypt with an insufficient work factor
 * @description Configuring BCrypt with a work factor (log rounds) below 10 makes password
 *              hashes cheap to brute-force.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/bcrypt-insufficient-work-factor
 * @tags security
 *       external/cwe/cwe-916
 */

import java

/** Gets the minimum acceptable BCrypt work factor (the Spring Security default). */
int minimumWorkFactor() { result = 10 }

/** A call that configures the BCrypt work factor through its only `int` argument. */
class BCryptWorkFactorCall extends Call {
  BCryptWorkFactorCall() {
    this.(ConstructorCall)
        .getConstructedType()
        .hasQualifiedName("org.springframework.security.crypto.bcrypt", "BCryptPasswordEncoder")
    or
    this.(MethodCall).getMethod().hasName("gensalt") and
    this.(MethodCall)
        .getMethod()
        .getDeclaringType()
        .hasQualifiedName(["org.mindrot.jbcrypt", "org.springframework.security.crypto.bcrypt"],
          "BCrypt")
  }

  /** Gets the work factor argument of this call. */
  Expr getWorkFactor() {
    result = this.getAnArgument() and result.getType().(PrimitiveType).hasName("int")
  }
}

from BCryptWorkFactorCall call, int factor
where
  factor = call.getWorkFactor().(CompileTimeConstantExpr).getIntValue() and
  factor < minimumWorkFactor()
select call,
  "BCrypt is configured with a work factor of " + factor +
    ", which is below the recommended minimum of " + minimumWorkFactor() + "."
