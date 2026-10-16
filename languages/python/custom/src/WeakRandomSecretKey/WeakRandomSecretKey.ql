/**
 * @name Secret key generated with a non-cryptographic random generator
 * @description Using the predictable `random` module to generate a signing or secret key
 *              (for example a JWT or session secret) allows an attacker to guess or
 *              brute-force the key and forge tokens.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id py/weak-random-secret-key
 * @tags security
 *       external/cwe/cwe-326
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** Gets the name of a `random` module function that returns a pseudo-random value. */
private string randomFunctionName() {
  result =
    [
      "choice", "choices", "getrandbits", "randbytes", "randint", "random", "randrange", "sample",
      "uniform", "triangular", "betavariate", "expovariate", "gammavariate", "gauss",
      "lognormvariate", "normalvariate", "paretovariate", "vonmisesvariate", "weibullvariate"
    ]
}

/** A call producing a value from the Mersenne Twister PRNG of the `random` module. */
class InsecureRandomCall extends API::CallNode {
  InsecureRandomCall() {
    this = API::moduleImport("random").getMember(randomFunctionName()).getACall()
    or
    this =
      API::moduleImport("random")
          .getMember("Random")
          .getReturn()
          .getMember(randomFunctionName())
          .getACall()
  }
}

/** Holds if `name` suggests that the named value holds a secret or signing key. */
bindingset[name]
predicate isSecretKeyName(string name) {
  name.regexpMatch("(?i).*(secret|(signing|jwt|hmac|api|private|encryption|session)_?key).*")
}

/** A value that is used as a secret or signing key. */
class SecretKeySink extends DataFlow::Node {
  SecretKeySink() {
    // `SECRET_KEY = ...` (module, class or function scope)
    exists(AssignStmt assign |
      isSecretKeyName(assign.getATarget().(Name).getId()) and
      this.asExpr() = assign.getValue()
    )
    or
    // `app.secret_key = ...`
    exists(DataFlow::AttrWrite write |
      isSecretKeyName(write.getAttributeName()) and
      this = write.getValue()
    )
    or
    // `app.config["SECRET_KEY"] = ...`
    exists(AssignStmt assign, Subscript sub |
      sub = assign.getATarget() and
      isSecretKeyName(sub.getIndex().(StringLiteral).getText()) and
      this.asExpr() = assign.getValue()
    )
    or
    // `jwt.encode(payload, key)` / `jwt.decode(token, key)` (PyJWT and python-jose)
    this =
      [API::moduleImport("jwt"), API::moduleImport("jose").getMember("jwt")]
          .getMember(["encode", "decode"])
          .getACall()
          .getParameter(1, "key")
          .asSink()
    or
    // `hmac.new(key, msg, digestmod)`
    this = API::moduleImport("hmac").getMember("new").getACall().getParameter(0, "key").asSink()
  }
}

module WeakRandomSecretKeyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof InsecureRandomCall }

  predicate isSink(DataFlow::Node sink) { sink instanceof SecretKeySink }

  // Only report the first place a weak value becomes a key, not every later use of that key.
  predicate isBarrierOut(DataFlow::Node node) { isSink(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module WeakRandomSecretKeyFlow = TaintTracking::Global<WeakRandomSecretKeyConfig>;

import WeakRandomSecretKeyFlow::PathGraph

from WeakRandomSecretKeyFlow::PathNode source, WeakRandomSecretKeyFlow::PathNode sink
where WeakRandomSecretKeyFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This secret key is derived from a $@ produced by the non-cryptographic `random` module.",
  source.getNode(), "pseudo-random value"
