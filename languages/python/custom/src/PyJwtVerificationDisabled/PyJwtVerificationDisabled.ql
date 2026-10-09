/**
 * @name JWT decoded with signature verification disabled
 * @description Decoding a JSON Web Token with signature verification disabled lets an
 *              attacker forge arbitrary claims, for example to impersonate another user.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id py/jwt-signature-verification-disabled
 * @tags security
 *       external/cwe/cwe-347
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

/**
 * A call that decodes a JWT and accepts an `options` dictionary in which
 * `verify_signature` can be turned off.
 */
class JwtDecodeCall extends DataFlow::CallCfgNode {
  boolean isPyJwt;

  JwtDecodeCall() {
    exists(API::Node jwtModule | jwtModule = API::moduleImport("jwt") |
      this =
        [jwtModule, jwtModule.getMember("api_jwt"), jwtModule.getMember("PyJWT").getReturn()]
            .getMember(["decode", "decode_complete"])
            .getACall()
    ) and
    isPyJwt = true
    or
    this = API::moduleImport("jose").getMember("jwt").getMember("decode").getACall() and
    isPyJwt = false
  }

  /** Gets the token argument. */
  DataFlow::Node getToken() { result in [this.getArg(0), this.getArgByName(["jwt", "token"])] }

  /** Gets the `options` argument. */
  DataFlow::Node getOptions() { result in [this.getArg(3), this.getArgByName("options")] }

  /** Gets the legacy (PyJWT 1.x) `verify` argument. */
  DataFlow::Node getVerify() {
    isPyJwt = true and
    result in [this.getArg(2), this.getArgByName("verify")]
  }
}

/** Flow of a `False` literal into a setting that disables JWT signature verification. */
private module DisabledVerificationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof False }

  predicate isSink(DataFlow::Node sink) {
    exists(JwtDecodeCall call | sink = [call.getOptions(), call.getVerify()])
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    isSink(node) and
    exists(DataFlow::DictionaryElementContent content |
      content.getKey() = "verify_signature" and
      c.isSingleton(content)
    )
  }
}

private module DisabledVerificationFlow = DataFlow::Global<DisabledVerificationConfig>;

/** Holds if `call` decodes a JWT with signature verification disabled by `source`. */
predicate disablesVerification(JwtDecodeCall call, DataFlow::Node source) {
  exists(DataFlow::Node sink |
    DisabledVerificationFlow::flow(source, sink) and
    sink = [call.getOptions(), call.getVerify()]
  )
}

/**
 * Holds if the token decoded by `call` is also decoded with signature verification
 * in the same scope, as when unverified claims are only read to select a key.
 */
predicate tokenIsVerifiedElsewhere(JwtDecodeCall call) {
  exists(JwtDecodeCall other |
    other != call and
    other.getScope() = call.getScope() and
    other.getToken().getALocalSource() = call.getToken().getALocalSource() and
    not disablesVerification(other, _)
  )
}

from JwtDecodeCall call, DataFlow::Node source
where
  disablesVerification(call, source) and
  not tokenIsVerifiedElsewhere(call)
select call, "This JWT is decoded with signature verification disabled by $@.", source, "this value"
