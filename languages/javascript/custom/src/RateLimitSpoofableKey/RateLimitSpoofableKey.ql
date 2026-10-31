/**
 * @name Rate limiter keyed on a spoofable client address
 * @description A rate limiter that identifies clients by a value the client controls, such as
 *              the `X-Forwarded-For` header, can be bypassed by sending a different value with
 *              each request.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id js/rate-limit-spoofable-key
 * @tags security
 *       external/cwe/cwe-307
 *       external/cwe/cwe-348
 */

import javascript

/** Gets the name of a rate-limiting package whose options take a `keyGenerator` function. */
private string rateLimiterPackage() { result = ["express-rate-limit", "express-slow-down"] }

/** A call that creates an `express-rate-limit` (or `express-slow-down`) middleware. */
class RateLimiterCreation extends DataFlow::InvokeNode {
  RateLimiterCreation() {
    exists(API::Node mod | mod = API::moduleImport(rateLimiterPackage()) |
      this = [mod, mod.getMember(["rateLimit", "slowDown", "default"])].getAnInvocation()
    )
  }

  /** Gets the function used by this rate limiter to compute the key that identifies a client. */
  DataFlow::FunctionNode getKeyGenerator() {
    result = this.getOptionArgument(0, "keyGenerator").getALocalSource()
  }
}

/** Gets a reference to the request object passed to the key generator `keyGen`. */
private DataFlow::SourceNode keyGeneratorRequest(
  DataFlow::FunctionNode keyGen, DataFlow::TypeTracker t
) {
  t.start() and
  keyGen = any(RateLimiterCreation c).getKeyGenerator() and
  result = keyGen.getParameter(0)
  or
  exists(DataFlow::TypeTracker t2 | result = keyGeneratorRequest(keyGen, t2).track(t2, t))
}

/** Gets a reference to the request object passed to the key generator `keyGen`. */
private DataFlow::SourceNode keyGeneratorRequest(DataFlow::FunctionNode keyGen) {
  result = keyGeneratorRequest(keyGen, DataFlow::TypeTracker::end())
}

/** Gets the lower-case name of a request header that conventionally carries a client IP address. */
private string clientIpHeader() {
  result =
    [
      "x-forwarded-for", "x-real-ip", "forwarded", "forwarded-for", "x-forwarded", "x-client-ip",
      "true-client-ip", "cf-connecting-ip", "fastly-client-ip", "x-cluster-client-ip"
    ]
}

/**
 * Holds if the application trusts any number of proxies (`app.enable('trust proxy')` or
 * `app.set('trust proxy', true)`), so that `req.ip` and `req.ips` are taken from the
 * client-supplied `X-Forwarded-For` header.
 */
private predicate trustsAllProxies() {
  exists(DataFlow::MethodCallNode call |
    call.getArgument(0).getStringValue() = "trust proxy" and
    (
      call.getMethodName() = "enable" and call.getNumArgument() = 1
      or
      call.getMethodName() = "set" and
      call.getArgument(1).asExpr().(BooleanLiteral).getBoolValue() = true
    )
  )
}

/** A client-controlled value read from the request passed to a rate-limiter key generator. */
class SpoofableClientAddress extends DataFlow::Node {
  string description;

  SpoofableClientAddress() {
    exists(DataFlow::SourceNode req | req = keyGeneratorRequest(_) |
      exists(string header | header = clientIpHeader() |
        (
          this =
            req.getAPropertyRead("headers")
                .getAPropertyRead(any(string h | h.toLowerCase() = header))
          or
          this = req.getAMethodCall(["get", "header"]) and
          this.(DataFlow::MethodCallNode).getArgument(0).getStringValue().toLowerCase() = header
        ) and
        description = "the client-supplied '" + header + "' header"
      )
      or
      trustsAllProxies() and
      this = req.getAPropertyRead(["ip", "ips"]) and
      description =
        "the client address, which is taken from the client-supplied 'X-Forwarded-For' header because all proxies are trusted"
    )
  }

  /** Gets a description of this value for use in an alert message. */
  string getDescription() { result = description }
}

module RateLimitSpoofableKeyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SpoofableClientAddress }

  predicate isSink(DataFlow::Node sink) {
    sink = any(RateLimiterCreation c).getKeyGenerator().getAReturn()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module RateLimitSpoofableKeyFlow = TaintTracking::Global<RateLimitSpoofableKeyConfig>;

import RateLimitSpoofableKeyFlow::PathGraph

from
  RateLimitSpoofableKeyFlow::PathNode source, RateLimitSpoofableKeyFlow::PathNode sink,
  RateLimiterCreation limiter
where
  RateLimitSpoofableKeyFlow::flowPath(source, sink) and
  sink.getNode() = limiter.getKeyGenerator().getAReturn()
select sink.getNode(), source, sink,
  "This rate-limiting key depends on $@, so a client can evade the $@ by changing it.",
  source.getNode(), source.getNode().(SpoofableClientAddress).getDescription(), limiter,
  "rate limiter"
