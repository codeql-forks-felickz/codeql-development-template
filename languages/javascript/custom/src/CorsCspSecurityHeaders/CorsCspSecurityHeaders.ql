/**
 * @name Cross-origin exposure of user data
 * @description Serving data from an authenticated session as JSONP, or sending
 *              user-entered data to another window with an unrestricted target
 *              origin, lets an attacker-controlled origin read the data.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id js/cross-origin-user-data-exposure
 * @tags security
 *       external/cwe/cwe-346
 *       external/cwe/cwe-942
 */

import javascript
import semmle.javascript.security.dataflow.XssThroughDomCustomizations

/**
 * Gets a read of request state that is populated from ambient credentials
 * (cookies, or a session or user established from them). Browsers attach
 * cookies to cross-origin `<script>` requests, so these values are available
 * when a third-party page includes a JSONP endpoint.
 */
DataFlow::SourceNode credentialRead(Express::RequestSource req) {
  result = req.ref().getAPropertyRead(["cookies", "signedCookies", "session", "user"])
  or
  result = req.ref().getAPropertyRead("headers").getAPropertyRead("cookie")
}

/** A call to `res.jsonp(...)` on an Express response. */
class JsonpCall extends DataFlow::MethodCallNode {
  JsonpCall() { this = any(Express::ResponseSource res).ref().getAMethodCall("jsonp") }
}

/**
 * Holds if `call` returns non-constant data as JSONP from the same function
 * that reads the credential-derived value `cred` (the first such read is chosen).
 */
predicate jsonpOfAuthenticatedData(JsonpCall call, DataFlow::Node cred) {
  exists(Expr data | data = call.getArgument(0).asExpr() |
    not data instanceof Literal and
    not data instanceof ConstantString
  ) and
  cred =
    min(DataFlow::SourceNode read, Location loc |
      read = credentialRead(_) and
      read.getContainer() = call.getContainer() and
      loc = read.getAstNode().getLocation()
    |
      read order by loc.getStartLine(), loc.getStartColumn()
    )
}

/**
 * Taint configuration for user-entered DOM data that reaches the message
 * argument of `postMessage(message, "*")`.
 */
module PostMessageStarUserDataConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof XssThroughDom::Source }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode postMessage |
      postMessage.getMethodName() = "postMessage" and
      postMessage.getArgument(1).mayHaveStringValue("*") and
      sink = postMessage.getArgument(0)
    )
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet contents) {
    // Also report objects containing user-entered data, e.g. `{ comment: input.value }`.
    isSink(node) and contents = DataFlow::ContentSet::anyProperty()
  }
}

module PostMessageStarUserDataFlow = TaintTracking::Global<PostMessageStarUserDataConfig>;

from DataFlow::Node alert, DataFlow::Node source, string message, string sourceDesc
where
  exists(JsonpCall call |
    jsonpOfAuthenticatedData(call, source) and
    alert = call and
    message =
      "This JSONP response exposes data from an $@ to any origin that includes it as a script." and
    sourceDesc = "authenticated request"
  )
  or
  exists(DataFlow::Node sink |
    PostMessageStarUserDataFlow::flow(source, sink) and
    alert = sink and
    message = "$@ is sent to another window without restricting the target origin." and
    sourceDesc = "User-entered data"
  )
select alert, message, source, sourceDesc
