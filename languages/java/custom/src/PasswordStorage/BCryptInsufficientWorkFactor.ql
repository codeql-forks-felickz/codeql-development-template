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
        .hasQualifiedName("org.springframework.security.crypto.bcrypt", "BCryptPasswordEncoder") and
    not isVerificationOnly(this.(ConstructorCall))
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

/** Holds if a locally scoped encoder is used only for verification and does not escape. */
private predicate isVerificationOnly(ConstructorCall constructor) {
  exists(LocalVariableDecl encoder |
    encoder.getInitializer() = constructor and
    not exists(AssignExpr assignment | assignment.getDest() = encoder.getAnAccess()) and
    exists(MethodCall verification |
      verification.getQualifier() = encoder.getAnAccess() and
      verification.getMethod().hasName(["matches", "upgradeEncoding"])
    ) and
    forall(VarRead access | access.getVariable() = encoder |
      exists(MethodCall verification |
        verification.getQualifier() = access and
        verification.getMethod().hasName(["matches", "upgradeEncoding"])
      )
    )
  )
}

from BCryptWorkFactorCall call, int factor
where
  factor = call.getWorkFactor().(CompileTimeConstantExpr).getIntValue() and
  factor >= 4 and factor < minimumWorkFactor()
select call,
  "BCrypt is configured with a work factor of " + factor +
    ", which is below the recommended minimum of " + minimumWorkFactor() + "."
