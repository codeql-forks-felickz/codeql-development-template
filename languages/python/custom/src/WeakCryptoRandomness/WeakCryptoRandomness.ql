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
      + "otp|csrf|xsrf|auth_?(key|code)|reset_?(code|key)|verification_?code|private_?key|" +
      "signing_?key|encryption_?key|access_?key).*") and
  not name.regexpMatch("(?i).*(len(gth)?|size|count|timeout|expir|delay|interval|ttl|name|type|field|header|label|url|path)$")
}

/** Holds if `name` looks like a function that generates a secret value. */
bindingset[name]
predicate isSecretGeneratorName(string name) {
  name.regexpMatch("(?i).*((gen(erate)?|make|mk|create|new|issue)_?.*(key|token|nonce|salt|passw|secret|otp|session|csrf)"
      + "|(key|token|nonce|salt|password|secret|otp|session)_?gen(erate|erator)?).*")
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
      a.getValue() = this.asExpr() and
      target = a.getATarget()
    |
      isSensitiveName(target.(Name).getId())
      or
      isSensitiveName(target.(Attribute).getName())
      or
      isSensitiveName(target.(Subscript).getIndex().(StringLiteral).getText())
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

/** Gets the first sink (by location) reached by `source`, so each source is reported once. */
DataFlow::Node firstSink(DataFlow::Node source) {
  result =
    min(DataFlow::Node sink, Location loc |
      WeakCryptoRandomnessFlow::flow(source, sink) and loc = sink.getLocation()
    |
      sink order by loc.getFile().getAbsolutePath(), loc.getStartLine(), loc.getStartColumn()
    )
}

from WeakCryptoRandomnessFlow::PathNode source, WeakCryptoRandomnessFlow::PathNode sink
where
  WeakCryptoRandomnessFlow::flowPath(source, sink) and
  sink.getNode() = firstSink(source.getNode())
select sink.getNode(), source, sink,
  "This security-sensitive value depends on a $@, which is not cryptographically secure; use the 'secrets' module or 'os.urandom' instead.",
  source.getNode(), "weak pseudo-random value"
