/**
 * @name Insecure randomness used for one-time password or security token
 * @description Using a non-cryptographic pseudo-random number generator, such as
 *              `java.util.Random`, Kotlin's default collection shuffle or `Math.random()`,
 *              to generate a one-time password, verification code or security token allows
 *              an attacker to predict the generated value.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id java/weak-crypto-randomness
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.InsecureRandomnessQuery

/**
 * Gets `name` split on camelCase and `_` boundaries, lower-cased, with words joined
 * by `_` and surrounded by `_` (for example `generateOTPCode` -> `_generate_otp_code_`).
 */
bindingset[name]
private string normalizeName(string name) {
  result =
    "_" +
      name.regexpReplaceAll("([a-z0-9])([A-Z])", "$1_$2")
          .regexpReplaceAll("([A-Z])([A-Z][a-z])", "$1_$2")
          .toLowerCase() + "_"
}

/**
 * Holds if `name` suggests that it holds a one-time password, verification code
 * or security token that must be unpredictable.
 */
bindingset[name]
private predicate isOneTimeSecretName(string name) {
  exists(string n | n = normalizeName(name) |
    not n.regexpMatch(".*_(delay|timeout|retry|count|length|size|ttl|expiry|interval|attempts|max|min)_.*") and
    (
      n.regexpMatch(".*_(otps?|totp|hotp)_.*")
      or
      n.regexpMatch(".*_(one_?time|verification|verify|confirmation|activation|mfa|2_?fa|two_?(factor|fa)|reset|recovery|security|sms|login|auth)_(codes?|pins?|tokens?)_.*")
      or
      n.regexpMatch(".*_(session|csrf|xsrf|access|api|bearer|invite|magic_link)_(tokens?|keys?)_.*")
      or
      n.regexpMatch(".*_session_ids?_.*")
    )
  )
}

bindingset[name]
private predicate isPasswordResetMethodName(string name) {
  exists(string n | n = normalizeName(name) | n.regexpMatch(".*_password_resets?_.*"))
}

/**
 * A value that is used as a one-time password, verification code or security token:
 * a value assigned to a suitably named variable, passed to a suitably named
 * parameter or setter, or returned from a suitably named method.
 */
class OneTimeSecretSink extends DataFlow::Node {
  OneTimeSecretSink() {
    exists(Variable v | isOneTimeSecretName(v.getName()) | this.asExpr() = v.getAnAssignedValue())
    or
    exists(Call c, Callable callee, int i |
      callee = c.getCallee() and
      this.asExpr() = c.getArgument(i)
    |
      isOneTimeSecretName(callee.getParameter(i).getName())
      or
      callee.getName().matches("set%") and
      isOneTimeSecretName(callee.getName()) and
      (c.getNumArgument() = 1 or not callee.getParameter(i).getType() instanceof PrimitiveType)
    )
    or
    exists(ReturnStmt ret |
      this.asExpr() = ret.getResult() and
      (
        isOneTimeSecretName(ret.getEnclosingCallable().getName())
        or
        isPasswordResetMethodName(ret.getEnclosingCallable().getName())
      )
    )
  }
}

/**
 * The first element of a Kotlin collection shuffled with the default random source.
 */
private class KotlinShuffledFirstSource extends DataFlow::Node {
  KotlinShuffledFirstSource() {
    exists(MethodCall first, MethodCall shuffled |
      this.asExpr() = first and
      first.getMethod().hasQualifiedName("kotlin.collections", "CollectionsKt", "first") and
      first.getArgument(0) = shuffled and
      shuffled.getMethod().hasQualifiedName("kotlin.collections", "CollectionsKt", "shuffled") and
      shuffled.getNumArgument() = 1
    )
  }
}

/**
 * A taint-tracking configuration for insecure randomness flowing into a one-time
 * password, verification code or security token. Sources and flow steps are shared
 * with `java/insecure-randomness`.
 */
module WeakCryptoRandomnessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof InsecureRandomnessSource or
    src instanceof KotlinShuffledFirstSource
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof OneTimeSecretSink }

  predicate isBarrierIn(DataFlow::Node n) { isSource(n) }

  predicate isBarrierOut(DataFlow::Node n) { isSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    InsecureRandomnessConfig::isAdditionalFlowStep(n1, n2)
    or
    // A random array index influences the character read when constructing a token by permutation.
    exists(AssignExpr assignment, ArrayAccess access |
      assignment.getLeftOperand() = access and
      access.getType().hasName("char") and
      DataFlow::localFlow(n1, DataFlow::exprNode(access.getIndexExpr())) and
      n2.asExpr() = access.getArray()
    )
    or
    // `String.valueOf(<primitive>)` is modeled as a neutral (numeric) summary, but numeric
    // random values commonly become OTPs this way.
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("java.lang", "String", "valueOf") and
      mc.getArgument(0).getType() instanceof PrimitiveType and
      n1.asExpr() = mc.getArgument(0) and
      n2.asExpr() = mc
    )
  }
}

module WeakCryptoRandomnessFlow = TaintTracking::Global<WeakCryptoRandomnessConfig>;

import WeakCryptoRandomnessFlow::PathGraph

from WeakCryptoRandomnessFlow::PathNode source, WeakCryptoRandomnessFlow::PathNode sink
where
  WeakCryptoRandomnessFlow::flowPath(source, sink) and
  // Avoid duplicating results already reported by `java/insecure-randomness`.
  not exists(DataFlow::Node stockSink |
    stockSink instanceof InsecureRandomnessSink and
    InsecureRandomnessFlow::flow(source.getNode(), stockSink) and
    DataFlow::localFlow(sink.getNode(), stockSink)
  )
select sink.getNode(), source, sink,
  "This one-time password or security token is generated from a $@, which is predictable.",
  source.getNode(), "non-cryptographic random number generator"
