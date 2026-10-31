/**
 * @name Missing JWT signature check in hand-written JWT decoding
 * @description Splitting a user-provided JSON Web Token (JWT) and decoding its payload without
 *              verifying the signature segment allows an attacker to forge arbitrary claims.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id go/missing-jwt-signature-check-manual-decode
 * @tags security
 *       external/cwe/cwe-347
 */

import go

/** A call to `strings.Split` or `strings.SplitN` that splits a string on `"."`. */
class DotSplitCall extends DataFlow::CallNode {
  DotSplitCall() {
    this.getTarget().hasQualifiedName("strings", ["Split", "SplitN"]) and
    this.getArgument(1).getStringValue() = "."
  }
}

/** Gets a read of the second segment (the JWT payload) of the result of `split`. */
DataFlow::ElementReadNode payloadSegmentRead(DotSplitCall split) {
  SplitResultToElementReadFlow::flow(split.getResult(), result.getBase()) and
  result.getIndex().getIntValue() = 1
}

private module SplitResultToElementReadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DotSplitCall split | source = split.getResult())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::ElementReadNode read |
      sink = read.getBase() and
      read.getIndex().getIntValue() = 1
    )
  }
}

private module SplitResultToElementReadFlow = DataFlow::Global<SplitResultToElementReadConfig>;

/**
 * Holds if `pred` is the encoded input and `succ` the decoded output of a call to a base64
 * decoding method from `encoding/base64`.
 */
predicate base64DecodeStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::MethodCallNode call |
    call.getTarget().hasQualifiedName("encoding/base64", "Encoding", "DecodeString") and
    pred = call.getArgument(0) and
    succ = call.getResult(0)
    or
    call.getTarget().hasQualifiedName("encoding/base64", "Encoding", "Decode") and
    pred = call.getArgument(1) and
    succ.(DataFlow::PostUpdateNode).getPreUpdateNode() = call.getArgument(0)
  )
}

/** Holds if a signature-segment read reaches a comparison or verification call. */
predicate signatureReadReachesCall(
  DataFlow::ElementReadNode read, DataFlow::CallNode verificationCall
) {
  DataFlow::localFlow(read, verificationCall.getAnArgument())
  or
  exists(DataFlow::MethodCallNode decode |
    decode.getTarget().hasQualifiedName("encoding/base64", "Encoding", "DecodeString") and
    DataFlow::localFlow(read, decode.getArgument(0)) and
    DataFlow::localFlow(decode.getResult(0), verificationCall.getAnArgument())
  )
}

/** Holds if `call` is a recognized signature comparison or verification operation. */
predicate isSignatureComparisonOrVerification(DataFlow::CallNode call) {
  call.getTarget().hasQualifiedName("crypto/hmac", "Equal")
  or
  call.getTarget().hasQualifiedName("crypto/subtle", "ConstantTimeCompare")
  or
  call.getTarget().hasQualifiedName("crypto/ed25519", "Verify")
  or
  call.getTarget().hasQualifiedName("crypto/ecdsa", ["Verify", "VerifyASN1"])
  or
  call.getTarget().hasQualifiedName("crypto/rsa", ["VerifyPKCS1v15", "VerifyPSS"])
}

/** Holds if `f` checks a cryptographic signature, or calls a function that appears to do so. */
predicate verifiesSignature(FuncDef f) {
  exists(DataFlow::CallNode call | call.getRoot() = f |
    call.getTarget().getName().regexpMatch("(?i).*(verif|signature).*")
  )
  or
  // The signature segment of the token reaches a comparison or verification call.
  exists(DataFlow::ElementReadNode read, DotSplitCall split, DataFlow::CallNode call |
    split.getRoot() = f and
    DataFlow::localFlow(split.getResult(), read.getBase()) and
    read.getIndex().getIntValue() = 2 and
    call.getRoot() = f and
    isSignatureComparisonOrVerification(call) and
    signatureReadReachesCall(read, call)
  )
}

newtype TJwtState =
  /** The whole (still encoded) token. */
  TToken() or
  /** The encoded payload segment of the token. */
  TPayload() or
  /** The base64-decoded payload of the token. */
  TDecodedPayload()

module ManualJwtDecodeConfig implements DataFlow::StateConfigSig {
  class FlowState = TJwtState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof ActiveThreatModelSource and state = TToken()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    state = TDecodedPayload() and
    (
      sink =
        any(DataFlow::CallNode c | c.getTarget().hasQualifiedName("encoding/json", "Unmarshal"))
            .getArgument(0)
      or
      sink =
        any(DataFlow::CallNode c | c.getTarget().hasQualifiedName("encoding/json", "NewDecoder"))
            .getArgument(0)
    ) and
    not verifiesSignature(sink.getRoot())
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    exists(DotSplitCall split |
      node1 = split.getArgument(0) and
      node2 = payloadSegmentRead(split) and
      not verifiesSignature(split.getRoot()) and
      state1 = TToken() and
      state2 = TPayload()
    )
    or
    base64DecodeStep(node1, node2) and
    state1 = TPayload() and
    state2 = TDecodedPayload()
  }
}

module ManualJwtDecodeFlow = TaintTracking::GlobalWithState<ManualJwtDecodeConfig>;

import ManualJwtDecodeFlow::PathGraph

from ManualJwtDecodeFlow::PathNode source, ManualJwtDecodeFlow::PathNode sink
where ManualJwtDecodeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "The payload of this JWT from a $@ is decoded and used without verifying its signature.",
  source.getNode(), "user-controlled source"
