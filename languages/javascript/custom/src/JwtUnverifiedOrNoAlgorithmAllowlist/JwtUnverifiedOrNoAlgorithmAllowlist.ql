/**
 * @name JWT identity from unverified token or verification without algorithm allowlist
 * @description Deriving the caller identity from a JWT that was decoded without verifying its
 *              signature, or verifying a JWT with a public key but without restricting the
 *              accepted algorithms, allows an attacker to forge tokens.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id js/jwt-unverified-or-no-algorithm-allowlist
 * @tags security
 *       external/cwe/cwe-347
 *       external/cwe/cwe-327
 */

import javascript

/**
 * Holds if `call` decodes the JWT `token` without verifying its signature.
 */
predicate unverifiedJwtDecode(DataFlow::CallNode call, DataFlow::Node token) {
  token = call.getArgument(0) and
  (
    call = DataFlow::moduleMember(["jsonwebtoken", "jws"], "decode").getACall()
    or
    call = DataFlow::moduleMember("jose", "decodeJwt").getACall()
    or
    call = DataFlow::moduleImport("jwt-decode").getACall()
    or
    call = DataFlow::moduleMember("jwt-decode", ["jwtDecode", "default"]).getACall()
    or
    // `jwt-simple`'s `decode(token, key, noVerify)` with `noVerify` set to `true`
    call = DataFlow::moduleMember("jwt-simple", "decode").getACall() and
    call.getArgument(2).mayHaveBooleanValue(true)
    or
    // Manual base64(url) decoding of the payload segment, e.g. `base64url.decode(token.split(".")[1])`
    isBase64Decode(call) and
    exists(DataFlow::PropRead segment, DataFlow::MethodCallNode split |
      segment = token.getALocalSource() and
      segment.getPropertyName() = "1" and
      split = segment.getBase().getALocalSource() and
      split.getMethodName() = "split" and
      split.getArgument(0).mayHaveStringValue(".")
    )
  )
}

/** Holds if `call` decodes a base64 or base64url encoded string passed as its first argument. */
predicate isBase64Decode(DataFlow::CallNode call) {
  call = DataFlow::globalVarRef("atob").getACall()
  or
  call = DataFlow::globalVarRef("Buffer").getAMemberCall("from") and
  call.getArgument(1).mayHaveStringValue(["base64", "base64url"])
  or
  call = DataFlow::moduleImport(["base64url", "base-64", "js-base64"]).getACall()
  or
  call = DataFlow::moduleImport(["base64url", "base-64", "js-base64"]).getAMemberCall("decode")
  or
  exists(DataFlow::PropRead base64 |
    call.(DataFlow::MethodCallNode).getMethodName() = "decode" and
    base64 = call.(DataFlow::MethodCallNode).getReceiver().getALocalSource() and
    base64.getPropertyName().regexpMatch("(?i)base64(url)?")
  )
}

/**
 * Holds if `node` is passed to something that (heuristically) verifies a JWT.
 */
predicate isVerificationArgument(DataFlow::Node node) {
  exists(DataFlow::CallNode call | node = call.getAnArgument() |
    call.getCalleeName().regexpMatch("(?i).*verif.*")
    or
    call = DataFlow::moduleMember("jwt-simple", "decode").getACall() and
    not call.getArgument(2).mayHaveBooleanValue(true)
  )
}

module UnverifiedDecodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { unverifiedJwtDecode(_, sink) }
}

module UnverifiedDecodeFlow = TaintTracking::Global<UnverifiedDecodeConfig>;

module VerifiedDecodeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { UnverifiedDecodeFlow::flow(source, _) }

  predicate isSink(DataFlow::Node sink) { isVerificationArgument(sink) }
}

module VerifiedDecodeFlow = TaintTracking::Global<VerifiedDecodeConfig>;

/**
 * Holds if `key` is heuristically an asymmetric public key or certificate.
 */
predicate isPublicKey(DataFlow::Node key) {
  exists(DataFlow::Node src | src = key or src = key.getALocalSource() |
    src.asExpr().(VarAccess).getName().regexpMatch("(?i).*(public|pub_?key|cert).*")
    or
    src.asExpr().(PropAccess).getPropertyName().regexpMatch("(?i).*(public|pub_?key|cert).*")
    or
    exists(Expr e | e = src.asExpr().getAChildExpr*() |
      [e.(StringLiteral).getValue(), e.(TemplateElement).getValue()]
          .regexpMatch("(?s).*-----BEGIN (RSA |EC )?(PUBLIC KEY|CERTIFICATE)-----.*")
    )
    or
    exists(DataFlow::CallNode read |
      read = DataFlow::moduleMember("fs", ["readFileSync", "readFile"]).getACall() and
      read = src.getALocalSource() and
      read.getArgument(0).getStringValue().regexpMatch("(?i).*(\\.pub|public|\\.crt|\\.cer|cert).*")
    )
  )
}

/**
 * Holds if the options object passed as argument `i` of `call` is an object literal (or absent,
 * or a callback) that does not specify an `algorithms` allowlist.
 */
bindingset[i]
predicate lacksAlgorithmsOption(DataFlow::CallNode call, int i) {
  not exists(call.getOptionArgument(i, "algorithms")) and
  (
    not exists(call.getArgument(i))
    or
    call.getArgument(i).getALocalSource() instanceof DataFlow::FunctionNode
    or
    call.getArgument(i).getALocalSource() instanceof DataFlow::ObjectLiteralNode
  )
}

/**
 * Holds if `call` verifies a JWT using `key`, a public key, without an algorithm allowlist.
 */
predicate verifiedWithoutAlgorithmAllowlist(DataFlow::CallNode call, DataFlow::Node key) {
  isPublicKey(key) and
  (
    (
      call = DataFlow::moduleImport(["express-jwt", "koa-jwt"]).getACall() or
      call = DataFlow::moduleMember("express-jwt", ["expressjwt", "default"]).getACall()
    ) and
    key = call.getOptionArgument(0, "secret") and
    lacksAlgorithmsOption(call, 0)
    or
    call = DataFlow::moduleMember("jsonwebtoken", "verify").getACall() and
    key = call.getArgument(1) and
    lacksAlgorithmsOption(call, 2)
    or
    // `jws.verify(signature, key)` trusts the `alg` header of the token,
    // whereas `jws.verify(signature, algorithm, key)` pins the algorithm.
    call = DataFlow::moduleMember("jws", "verify").getACall() and
    call.getNumArgument() = 2 and
    key = call.getArgument(1)
  )
}

from DataFlow::Node alertNode, string message, DataFlow::Node ref, string refText
where
  exists(DataFlow::CallNode call, DataFlow::Node source, DataFlow::Node token |
    unverifiedJwtDecode(call, token) and
    UnverifiedDecodeFlow::flow(source, token) and
    not VerifiedDecodeFlow::flowFrom(source) and
    alertNode = call and
    message = "JWT is decoded without signature verification; the token comes from a $@." and
    ref = source and
    refText = "user-provided value"
  )
  or
  exists(DataFlow::CallNode call |
    verifiedWithoutAlgorithmAllowlist(call, ref) and
    alertNode = call and
    message =
      "JWT is verified with a $@ but without an algorithm allowlist, allowing algorithm confusion." and
    refText = "public key"
  )
select alertNode, message, ref, refText
