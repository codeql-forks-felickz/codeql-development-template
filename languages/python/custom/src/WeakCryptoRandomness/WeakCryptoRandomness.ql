/**
 * @name Weak randomness used for security-sensitive value
 * @description Using the non-cryptographic `random` module (Mersenne Twister) to generate API keys,
 *              tokens, passwords, nonces or other secrets allows an attacker who observes some
 *              outputs to recover the generator state and predict other values.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id py/custom/weak-crypto-randomness
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** Gets the name of a `random` PRNG function that returns a pseudo-random value. */
string prngFunctionName() {
  result =
    [
      "betavariate", "binomialvariate", "choice", "choices", "expovariate", "gammavariate", "gauss",
      "getrandbits", "lognormvariate", "normalvariate", "paretovariate", "randbytes", "randint",
      "random", "randrange", "sample", "triangular", "uniform", "vonmisesvariate", "weibullvariate"
    ]
}

/** Holds if `name` looks like it holds a secret, credential or other security-sensitive value. */
bindingset[name]
predicate isSensitiveName(string name) {
  name.regexpMatch("(?i).*(api_?key|secret|token|passw(or)?d|passwd|pwd|nonce|salt|session_?(id|key)|"
      + "otp|csrf|xsrf|auth_?(key|code)|reset_?(code|key)|verification_?code|referral_?code|" +
      "ticket_?(id|code|number)|private_?key|" + "signing_?key|encryption_?key|access_?key).*") and
  not name.regexpMatch("(?i).*(secretar|tokeniz|keypoint).*") and
  not isNonSecretSuffix(name)
}

/** Holds if `name` ends in a suffix that indicates a non-secret value. */
bindingset[name]
predicate isNonSecretSuffix(string name) {
  name.regexpMatch("(?i).*(len(gth)?|size|count|timeout|expir(e|y|ation|es)?(_at)?|delay|interval|ttl|name|type|field|header|label|url|path)$")
}

/** Holds if `name` looks like a function that generates a secret value. */
bindingset[name]
predicate isSecretGeneratorName(string name) {
  name.regexpMatch("(?i).*((gen(erate)?|make|mk|create|new|issue)_?.*(key|token|nonce|salt|passw|secret|otp|session|csrf)"
      + "|(key|token|nonce|salt|password|secret|otp|session)_?gen(erate|erator)?).*") and
  not name.regexpMatch("(?i).*(secretar|tokeniz|keypoint).*") and
  not isNonSecretSuffix(name)
}

/** Holds if assigning `value` to `target` stores it in a sensitive name. */
predicate isSensitiveAssignmentValue(Expr target, Expr value, Expr sensitiveValue) {
  (
    isSensitiveName(target.(Name).getId()) or
    isSensitiveName(target.(Attribute).getName()) or
    isSensitiveName(target.(Subscript).getIndex().(StringLiteral).getText())
  ) and
  sensitiveValue = value
  or
  exists(int index, Expr targetElement, Expr valueElement |
    (
      targetElement = target.(Tuple).getElt(index)
      or
      targetElement = target.(List).getElt(index)
    ) and
    (
      valueElement = value.(Tuple).getElt(index)
      or
      valueElement = value.(List).getElt(index)
    ) and
    isSensitiveAssignmentValue(targetElement, valueElement, sensitiveValue)
  )
}

/** Holds if `assignment` builds the value of a session cookie. */
predicate isSessionCookieAssignment(AssignStmt assignment) {
  exists(Name target, StringLiteral cookieName |
    target = assignment.getATarget() and
    target.getId() = "cookie" and
    assignment.getValue().getASubExpression*() = cookieName and
    cookieName.getText().regexpMatch("(?i).*sessionid\\s*=.*")
  )
}

/** A call to a `random` PRNG function that is not cryptographically secure. */
class WeakRandomSource extends DataFlow::CallCfgNode {
  WeakRandomSource() {
    this = API::moduleImport("random").getMember(prngFunctionName()).getACall()
    or
    this =
      API::moduleImport("random")
          .getMember("Random")
          .getReturn()
          .getMember(prngFunctionName())
          .getACall()
  }
}

/** A security-sensitive use of a value, where weak randomness must not be used. */
class SecuritySensitiveSink extends DataFlow::Node {
  SecuritySensitiveSink() {
    // input to a cryptographic operation, e.g. `hashlib.sha256(x)`
    this = any(Cryptography::CryptographicOperation op).getAnInput()
    or
    // assignment to a sensitive variable, attribute or string-keyed subscript
    exists(AssignStmt a, Expr target |
      target = a.getATarget() and
      isSensitiveAssignmentValue(target, a.getValue(), this.asExpr())
    )
    or
    // value assigned to a session cookie string
    exists(AssignStmt a |
      isSessionCookieAssignment(a) and
      this.asExpr() = a.getValue()
    )
    or
    // value assigned to a sensitive string key in a dictionary literal
    exists(AssignStmt a, Dict dict, KeyValuePair item |
      a.getValue() = dict and
      item = dict.getAnItem() and
      isSensitiveName(item.getKey().(StringLiteral).getText()) and
      this.asExpr() = item.getValue()
    )
    or
    // keyword argument with a sensitive name, e.g. `User(api_key=x)`
    exists(DataFlow::CallCfgNode call, string name |
      this = call.getArgByName(name) and isSensitiveName(name)
    )
    or
    // value returned from a secret generator function, e.g. `def generate_token(): return x`
    exists(Return r |
      isSecretGeneratorName(r.getScope().(Function).getName()) and
      this.asExpr() = r.getValue()
    )
  }
}

module WeakCryptoRandomnessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof WeakRandomSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SecuritySensitiveSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // encoding a weak random value preserves its predictability, e.g. `random.randbytes(16).hex()`
    exists(DataFlow::MethodCallNode call |
      call.calls(pred, ["hex", "hexdigest", "digest", "decode", "encode", "to_bytes"]) and
      succ = call
    )
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }
}

module WeakCryptoRandomnessFlow = TaintTracking::Global<WeakCryptoRandomnessConfig>;

import WeakCryptoRandomnessFlow::PathGraph

/** Holds if an earlier sink locally flows to `sink`, so both sinks report only once for that value. */
predicate hasPrecedingSinkOnSameValue(DataFlow::Node sink) {
  exists(DataFlow::Node earlierSink, Location earlierLocation, Location sinkLocation |
    WeakCryptoRandomnessConfig::isSink(earlierSink) and
    earlierLocation = earlierSink.getLocation() and
    sinkLocation = sink.getLocation() and
    earlierLocation.getFile().getAbsolutePath() = sinkLocation.getFile().getAbsolutePath() and
    (
      earlierLocation.getStartLine() < sinkLocation.getStartLine()
      or
      earlierLocation.getStartLine() = sinkLocation.getStartLine() and
      earlierLocation.getStartColumn() < sinkLocation.getStartColumn()
    ) and
    DataFlow::localFlow(earlierSink, sink)
  )
}

from WeakCryptoRandomnessFlow::PathNode source, WeakCryptoRandomnessFlow::PathNode sink
where
  WeakCryptoRandomnessFlow::flowPath(source, sink) and
  not hasPrecedingSinkOnSameValue(sink.getNode())
select sink.getNode(), source, sink,
  "This security-sensitive value depends on a $@, which is not cryptographically secure; use the 'secrets' module or 'os.urandom' instead.",
  source.getNode(), "weak pseudo-random value"
