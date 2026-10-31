/**
 * @name JWT signed or accepted without signature verification
 * @description Using the 'none' algorithm or accepting decoded JWT claims without
 *              signature verification allows forged or modified tokens to be trusted.
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
import semmle.code.java.controlflow.Dominance
import semmle.code.java.controlflow.Guards
import semmle.code.java.frameworks.Servlets

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

/** A method-local, value-preserving relationship, including aliases of the same value. */
private predicate sameLocalValue(Expr first, Expr second) {
  exists(DataFlow::Node value |
    DataFlow::localFlow(value, DataFlow::exprNode(first)) and
    DataFlow::localFlow(value, DataFlow::exprNode(second))
  )
}

/** Verification with a demonstrably `none` algorithm provides no signature check. */
private predicate usesNoneVerification(MethodCall verify) {
  exists(Auth0NoneAlgorithm algorithm | DataFlow::localExprFlow(algorithm, verify.getQualifier()))
  or
  exists(MethodCall require, MethodCall build |
    require.getMethod().hasQualifiedName("com.auth0.jwt", "JWT", "require") and
    NoneAlgorithmFlow::flow(_, DataFlow::exprNode(require.getArgument(0))) and
    build.getMethod().getName() = "build" and
    build
        .getMethod()
        .getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("com.auth0.jwt.interfaces", "Verification") and
    DataFlow::localExprFlow(require, build.getQualifier()) and
    DataFlow::localExprFlow(build, verify.getQualifier())
  )
}

/** A successfully completed Auth0 verification of this token dominates the acceptance use. */
private predicate verifiedBefore(MethodCall decode, ControlFlowNode acceptance) {
  exists(MethodCall verify |
    verify.getEnclosingCallable() = decode.getEnclosingCallable() and
    (
      verify.getMethod().hasQualifiedName("com.auth0.jwt", "JWTVerifier", "verify") or
      verify.getMethod().hasQualifiedName("com.auth0.jwt.interfaces", "JWTVerifier", "verify") or
      verify.getMethod().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm", "verify")
    ) and
    (
      sameLocalValue(decode.getArgument(0), verify.getArgument(0)) or
      DataFlow::localExprFlow(decode, verify.getArgument(0))
    ) and
    not usesNoneVerification(verify) and
    dominates(verify.getControlFlowNode(), acceptance) and
    dominates(verify.getControlFlowNode().getANormalSuccessor(), acceptance)
  )
}

/** A successful validator return or a Spring model update in the matching branch. */
private predicate isAcceptanceUse(ControlFlowNode acceptance) {
  acceptance.asStmt().(ReturnStmt).getExpr().(BooleanLiteral).getBooleanValue() = true
  or
  exists(MethodCall update |
    acceptance.asExpr() = update and
    update.getMethod().getName() = "addAttribute" and
    update
        .getMethod()
        .getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("org.springframework.ui", "Model")
  )
}

/** A decoded string claim comparison that controls an unchecked acceptance use. */
private predicate unverifiedSessionComparison(MethodCall decode, MethodCall comparison) {
  decode.getMethod().hasQualifiedName("com.auth0.jwt", "JWT", "decode") and
  decode.getEnclosingCallable() = comparison.getEnclosingCallable() and
  exists(
    MethodCall claim, MethodCall text, MethodCall attribute, Expr claimValue, Expr sessionValue
  |
    claim.getMethod().hasQualifiedName("com.auth0.jwt.interfaces", "Payload", "getClaim") and
    text.getMethod().hasQualifiedName("com.auth0.jwt.interfaces", "Claim", "asString") and
    DataFlow::localExprFlow(decode, claim.getQualifier()) and
    DataFlow::localExprFlow(claim, text.getQualifier()) and
    attribute.getMethod().getDeclaringType() instanceof HttpServletSession and
    attribute.getMethod().getName() = "getAttribute" and
    claim.getArgument(0).(CompileTimeConstantExpr).getStringValue() =
      attribute.getArgument(0).(CompileTimeConstantExpr).getStringValue() and
    comparison.getMethod().hasQualifiedName("java.lang", "String", ["equals", "equalsIgnoreCase"]) and
    (
      claimValue = comparison.getQualifier() and sessionValue = comparison.getArgument(0)
      or
      claimValue = comparison.getArgument(0) and sessionValue = comparison.getQualifier()
    ) and
    DataFlow::localExprFlow(text, claimValue) and
    DataFlow::localExprFlow(attribute, sessionValue)
  ) and
  exists(ConditionBlock condition, ControlFlowNode acceptance |
    DataFlow::localExprFlow(comparison, condition.getCondition().(Expr)) and
    condition.controls(acceptance.getBasicBlock(), true) and
    isAcceptanceUse(acceptance) and
    not verifiedBefore(decode, acceptance)
  )
}

from Expr use, DataFlow::Node source, string message, string sourceLabel
where
  exists(DataFlow::Node sink, Auth0AlgorithmUse algorithmUse |
    NoneAlgorithmFlow::flow(source, sink) and
    algorithmUse = sink.asExpr() and
    use = algorithmUse and
    message =
      "This JWT is " + algorithmUse.getUse() + " with the $@, so its signature is never checked." and
    sourceLabel = "'none' algorithm"
  )
  or
  exists(MethodCall decode, MethodCall comparison |
    unverifiedSessionComparison(decode, comparison) and
    use = comparison and
    source = DataFlow::exprNode(decode) and
    message = "This comparison trusts a claim from $@ without verifying the token's signature." and
    sourceLabel = "a decoded JWT"
  )
select use, message, source, sourceLabel
