/**
 * @name Stored cross-site scripting through a request-controlled cookie
 * @description Writing user-provided request data into a cookie and later emitting that
 *              cookie into a page without escaping lets an attacker store a cross-site
 *              scripting payload in the victim's browser.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id rb/cookie-stored-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import codeql.ruby.AST
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.frameworks.Rails
import codeql.ruby.security.XSS
import CookieStoredXssFlow::PathGraph

/**
 * Gets a reference to the Rails cookie jar, including the `permanent`, `signed`
 * and `encrypted` derived jars.
 */
DataFlow::LocalSourceNode cookieJar() {
  result.asExpr().getExpr() instanceof Rails::CookiesCall
  or
  result = cookieJar().getAMethodCall(["permanent", "signed", "encrypted"])
}

/** Gets the serialization kind of a Rails cookie jar. */
predicate cookieJarKind(DataFlow::LocalSourceNode jar, string kind) {
  jar.asExpr().getExpr() instanceof Rails::CookiesCall and kind = "plain"
  or
  exists(DataFlow::LocalSourceNode base, string baseKind |
    jar = base.getAMethodCall("permanent") and
    cookieJarKind(base, baseKind) and
    kind = baseKind
  )
  or
  exists(DataFlow::LocalSourceNode base |
    jar = base.getAMethodCall("signed") and
    cookieJarKind(base, _) and
    kind = "signed"
  )
  or
  exists(DataFlow::LocalSourceNode base |
    jar = base.getAMethodCall("encrypted") and
    cookieJarKind(base, _) and
    kind = "encrypted"
  )
}

/** A write to a cookie with a constant name, such as `cookies[:font] = value`. */
class CookieWrite extends DataFlow::CallNode {
  string name;
  string jarKind;

  CookieWrite() {
    this = cookieJar().getAMethodCall("[]=") and
    name = this.getArgument(0).getConstantValue().getStringlikeValue() and
    cookieJarKind(this.getReceiver(), jarKind)
  }

  /** Gets the name of the written cookie. */
  string getCookieName() { result = name }

  /** Gets the value written to the cookie. */
  DataFlow::Node getValue() { result = this.getArgument(1) }

  /** Gets the serialization kind of the jar the cookie was written to. */
  string getCookieJarKind() { result = jarKind }
}

/** A read of a cookie with a constant name, such as `cookies[:font]`. */
class CookieRead extends DataFlow::CallNode {
  string name;
  string jarKind;

  CookieRead() {
    this = cookieJar().getAMethodCall(["[]", "fetch"]) and
    name = this.getArgument(0).getConstantValue().getStringlikeValue() and
    cookieJarKind(this.getReceiver(), jarKind)
  }

  /** Gets the name of the read cookie. */
  string getCookieName() { result = name }

  /** Gets the serialization kind of the jar the cookie was read from. */
  string getCookieJarKind() { result = jarKind }
}

/**
 * Tracks third-party controllable request input (for example `params`) into a
 * cookie written by the application, and from a read of that same cookie into a
 * server-side XSS sink. The flow state records whether the value has been
 * stored in a cookie, so that ordinary reflected XSS (already reported by
 * `rb/reflected-xss`) is not reported again.
 */
module CookieStoredXssConfig implements DataFlow::StateConfigSig {
  /** Holds if the tracked value has been stored in, and read back from, a cookie. */
  class FlowState = boolean;

  predicate isSource(DataFlow::Node source, FlowState stored) {
    source instanceof ReflectedXss::Source and stored = false
  }

  predicate isSink(DataFlow::Node sink, FlowState stored) {
    sink instanceof ReflectedXss::Sink and stored = true
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof ReflectedXss::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    ReflectedXss::isAdditionalXssTaintStep(node1, node2)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    exists(CookieWrite write, CookieRead read |
      node1 = write.getValue() and
      node2 = read and
      write.getCookieName() = read.getCookieName() and
      write.getCookieJarKind() = read.getCookieJarKind() and
      state1 = false and
      state2 = true
    )
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    // `cookies[:name] = { value: params[:x], expires: ... }`
    node = any(CookieWrite write).getValue() and
    exists(DataFlow::Content::KnownElementContent value |
      c.isSingleton(value) and value.getIndex().getStringlikeValue() = "value"
    )
  }
}

module CookieStoredXssFlow = TaintTracking::GlobalWithState<CookieStoredXssConfig>;

from CookieStoredXssFlow::PathNode source, CookieStoredXssFlow::PathNode sink
where CookieStoredXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to a $@ that is stored in a cookie.", source.getNode(),
  "user-provided value"
