/**
 * Provides a taint-tracking configuration for reasoning about clear-text
 * logging of authentication tokens (for example signed JWTs, access tokens,
 * refresh tokens and session tokens).
 *
 * The standard `go/clear-text-logging` query only treats password-like names,
 * HTTP request headers and Kubernetes secrets as sensitive. This library adds
 * token sources and reuses the standard logging sinks and barriers.
 */

import go
private import semmle.go.security.CleartextLoggingCustomizations as StdCleartextLogging

/**
 * Provides sources, sinks and barriers for clear-text logging of
 * authentication tokens.
 */
module CleartextTokenLogging {
  /** A data-flow source of an authentication token. */
  abstract class Source extends DataFlow::Node {
    Source() {
      // hard-coded strings are uninteresting
      not exists(this.getStringValue()) and
      // avoid duplicating results of the standard `go/clear-text-logging` query
      not this instanceof StdCleartextLogging::CleartextLogging::Source
    }

    /** Gets a string that describes this source. */
    abstract string describe();
  }

  /** A data-flow sink for clear-text logging of authentication tokens. */
  abstract class Sink extends DataFlow::Node { }

  /** A barrier for clear-text logging of authentication tokens. */
  abstract class Barrier extends DataFlow::Node { }

  /** Gets the import path of a JWT library modeled by this library. */
  private string jwtPackage() {
    result =
      package([
          "github.com/golang-jwt/jwt", "github.com/dgrijalva/jwt-go",
          "github.com/form3tech-oss/jwt-go"
        ], "")
  }

  /**
   * Gets a regular expression matching names that may refer to an
   * authentication token.
   */
  string maybeToken() { result = "(?is).*(token|jwt|bearer).*" }

  /**
   * Gets a regular expression matching names that refer to token metadata,
   * non-credential tokens, or obfuscated tokens rather than to a credential.
   */
  string notToken() {
    result =
      "(?is).*(csrf|xsrf|tokeni[sz]|type|kind|count|len|size|num|url|uri|endpoint|path|header|name|expir|ttl|lifetime|duration|timeout|valid|err|claim|cursor|page|next|test|redact|censor|obfuscat|mask|hash|digest|md5|sha|hmac|crypt|cipher).*"
  }

  /** Holds if `t` is a string or byte-slice type, possibly via a named type. */
  private predicate isStringLike(Type t) {
    t.getUnderlyingType() instanceof StringType or
    t.getUnderlyingType() instanceof ByteSliceType
  }

  /** Holds if `name` looks like the name of an authentication token. */
  bindingset[name]
  private predicate isTokenName(string name) {
    name.regexpMatch(maybeToken()) and
    not name.regexpMatch(notToken())
  }

  /** The string result of signing a JWT, for example `Token.SignedString`. */
  private class JwtSignedTokenSource extends Source {
    JwtSignedTokenSource() {
      exists(DataFlow::MethodCallNode c | this = c.getResult(0) |
        c.getTarget().hasQualifiedName(jwtPackage(), "Token", "SignedString")
        or
        c.getTarget().implements(jwtPackage(), "SigningMethod", "Sign")
      )
    }

    override string describe() { result = "a signed JWT" }
  }

  /** A read of a variable, parameter or field whose name suggests it holds a token. */
  private class TokenNameSource extends Source {
    string name;

    TokenNameSource() {
      isTokenName(name) and
      isStringLike(this.getType()) and
      (
        this.(DataFlow::SsaNode).getSourceVariable().getName() = name
        or
        this.(DataFlow::FieldReadNode).getFieldName() = name
      )
    }

    override string describe() { result = "an access to " + name }
  }

  /** The (first) result of a call to a function whose name suggests it returns a token. */
  private class TokenCallSource extends Source {
    string name;

    TokenCallSource() {
      exists(DataFlow::CallNode c |
        name = c.getCalleeName() and
        this = c.getResult(0) and
        isTokenName(name) and
        isStringLike(this.getType())
      )
    }

    override string describe() { result = "a call to " + name }
  }

  /** An argument to a logging mechanism, as modeled by the standard query. */
  private class LoggerSink extends Sink instanceof StdCleartextLogging::CleartextLogging::Sink { }

  /** A barrier from the standard clear-text logging library. */
  private class StdBarrier extends Barrier instanceof StdCleartextLogging::CleartextLogging::Barrier
  { }

  /** The result of a cryptographic operation, such as hashing or encrypting a token. */
  private class CryptoBarrier extends Barrier {
    CryptoBarrier() {
      exists(DataFlow::CallNode c | this = c.getResult(_) |
        c.getTarget().getPackage().getPath().regexpMatch("(crypto|golang\\.org/x/crypto)(/.*)?")
      )
    }
  }

  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) { source instanceof Source }

    predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

    predicate isBarrier(DataFlow::Node node) {
      node instanceof Barrier
      or
      exists(DataFlow::CallNode call | node = call.getResult() |
        call.getTarget() = Builtin::error().getType().getMethod("Error")
        or
        call.getTarget().(Method).hasQualifiedName("fmt", "Stringer", "String")
      )
    }

    predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

    predicate isAdditionalFlowStep(DataFlow::Node src, DataFlow::Node trg) {
      // A tainted field write taints the entire struct, as logging a struct shows its fields.
      exists(Write write | write.writesField(trg, _, src))
      or
      // Taint steps that do not include flow through fields, mirroring the standard query.
      TaintTracking::defaultAdditionalTaintStep(src, trg, _) and
      not TaintTracking::fieldReadStep(src, trg) and
      not any(Protobuf::GetMethod gm).taintStep(src, trg)
    }

    predicate observeDiffInformedIncrementalMode() { any() }
  }

  /** Tracks flow from authentication tokens to logging calls. */
  module Flow = DataFlow::Global<Config>;
}
