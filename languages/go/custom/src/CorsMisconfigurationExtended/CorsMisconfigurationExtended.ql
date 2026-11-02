/**
 * @name CORS misconfiguration (extended)
 * @description If a CORS policy accepts an origin obtained from the request data, the `null`
 *              origin, or any origin (`*`), and also allows credentials or state-changing
 *              methods, then other websites can read authenticated responses or make
 *              state-changing requests on behalf of users. This variant of
 *              `go/cors-misconfiguration` additionally reports wildcard origins set through
 *              `net/http` headers and through the Echo, gin-contrib/cors, rs/cors and
 *              go-chi/cors middleware configuration.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id go/cors-misconfiguration-extended
 * @tags security
 *       external/cwe/cwe-942
 *       external/cwe/cwe-346
 */

import go
import semmle.go.security.InsecureFeatureFlag::InsecureFeatureFlag

/*
 * The following definitions, up to and including `flowsToGuardedByCheckOnUntrusted`, are
 * taken unchanged from the experimental `go/cors-misconfiguration` query.
 */

/**
 * A flag indicating a check for satisfied permissions or test configuration.
 */
class AllowedFlag extends FlagKind {
  AllowedFlag() { this = "allowed" }

  bindingset[result]
  override string getAFlagName() {
    result.regexpMatch("(?i).*(allow|match|check|debug|devel|insecure).*")
  }
}

/**
 * Provides the name of the `Access-Control-Allow-Origin` header key.
 */
string headerAllowOrigin() { result = "Access-Control-Allow-Origin".toLowerCase() }

/**
 * Provides the name of the `Access-Control-Allow-Credentials` header key.
 */
string headerAllowCredentials() { result = "Access-Control-Allow-Credentials".toLowerCase() }

/**
 * An `Access-Control-Allow-Origin` header write.
 */
class AllowOriginHeaderWrite extends Http::HeaderWrite {
  AllowOriginHeaderWrite() { this.getHeaderName() = headerAllowOrigin() }
}

/**
 * An `Access-Control-Allow-Credentials` header write.
 */
class AllowCredentialsHeaderWrite extends Http::HeaderWrite {
  AllowCredentialsHeaderWrite() { this.getHeaderName() = headerAllowCredentials() }
}

module UntrustedToAllowOriginHeaderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  additional predicate isSinkHW(DataFlow::Node sink, AllowOriginHeaderWrite hw) {
    sink = hw.getValue()
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(ControlFlow::ConditionGuardNode cgn |
      cgn.ensures(any(AllowedFlag f).getAFlag().getANode(), _)
    |
      cgn.dominates(node.getBasicBlock())
    )
  }

  predicate isSink(DataFlow::Node sink) { isSinkHW(sink, _) }
}

module UntrustedToAllowOriginConfigConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  additional predicate isSinkWrite(DataFlow::Node sink, UniversalOriginWrite w) { sink = w }

  predicate isSink(DataFlow::Node sink) { isSinkWrite(sink, _) }
}

/**
 * Tracks taint flow for reasoning about when a `ActiveThreatModelSource` flows to
 * a `HeaderWrite` that writes an `Access-Control-Allow-Origin` header's value.
 */
module UntrustedToAllowOriginHeaderFlow = TaintTracking::Global<UntrustedToAllowOriginHeaderConfig>;

/**
 * Tracks taint flow for reasoning about when a `ActiveThreatModelSource` flows to
 * a `AllowOriginsWrite` that writes an `Access-Control-Allow-Origin` header's value.
 */
module UntrustedToAllowOriginConfigFlow = TaintTracking::Global<UntrustedToAllowOriginConfigConfig>;

/**
 * Holds if the provided `allowOriginHW` HeaderWrite's parent ResponseWriter
 * also has another HeaderWrite that sets a `Access-Control-Allow-Credentials`
 * header to `true`.
 */
predicate allowCredentialsIsSetToTrue(DataFlow::ExprNode allowOriginHW) {
  exists(AllowCredentialsHeaderWrite allowCredentialsHW |
    allowCredentialsHW.getHeaderValue().toLowerCase() = "true"
  |
    allowOriginHW.(AllowOriginHeaderWrite).getResponseWriter() =
      allowCredentialsHW.getResponseWriter()
  )
  or
  exists(UniversalAllowCredentialsWrite allowCredentialsGin |
    allowCredentialsGin.getExpr().getBoolValue() = true
  |
    allowCredentialsGin.getConfig() = allowOriginHW.(UniversalOriginWrite).getConfig() and
    not exists(UniversalAllowAllOriginsWrite allowAllOrigins |
      allowAllOrigins.getExpr().getBoolValue() = true and
      allowCredentialsGin.getConfig() = allowAllOrigins.getConfig()
    )
    or
    allowCredentialsGin.getBase() = allowOriginHW.(UniversalOriginWrite).getBase() and
    not exists(UniversalAllowAllOriginsWrite allowAllOrigins |
      allowAllOrigins.getExpr().getBoolValue() = true and
      allowCredentialsGin.getBase() = allowAllOrigins.getBase()
    )
  )
}

/**
 * Holds if the provided `allowOriginHW` HeaderWrite's value is set using an
 * ActiveThreatModelSource.
 * The `message` parameter is populated with the warning message to be returned by the query.
 */
predicate flowsFromUntrustedToAllowOrigin(DataFlow::ExprNode allowOriginHW, string message) {
  exists(DataFlow::Node sink |
    UntrustedToAllowOriginHeaderFlow::flowTo(sink) and
    UntrustedToAllowOriginHeaderConfig::isSinkHW(sink, allowOriginHW)
    or
    UntrustedToAllowOriginConfigFlow::flowTo(sink) and
    UntrustedToAllowOriginConfigConfig::isSinkWrite(sink, allowOriginHW)
  |
    message =
      headerAllowOrigin() + " header is set to a user-defined value, and " +
        headerAllowCredentials() + " is set to `true`"
  )
}

/**
 * Holds if the provided `allowOriginHW` HeaderWrite is for a `Access-Control-Allow-Origin`
 * header and the value is set to `null`.
 */
predicate allowOriginIsNull(DataFlow::ExprNode allowOriginHW, string message) {
  allowOriginHW.(AllowOriginHeaderWrite).getHeaderValue().toLowerCase() = "null" and
  message =
    headerAllowOrigin() + " header is set to `" +
      allowOriginHW.(AllowOriginHeaderWrite).getHeaderValue() + "`, and " + headerAllowCredentials()
      + " is set to `true`"
  or
  allowOriginHW
      .(UniversalOriginWrite)
      .asExpr()
      .(SliceLit)
      .getAnElement()
      .getStringValue()
      .toLowerCase() = "null" and
  message =
    headerAllowOrigin() + " header is set to `" + "null" + "`, and " + headerAllowCredentials() +
      " is set to `true`"
}

/**
 * A read on a map type.
 */
class MapRead extends DataFlow::ElementReadNode {
  MapRead() { this.getBase().getType() instanceof MapType }
}

module FromUntrustedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { isSinkCgn(sink, _) }

  additional predicate isSinkCgn(DataFlow::Node sink, ControlFlow::ConditionGuardNode cgn) {
    exists(IfStmt ifs |
      exists(Expr operand |
        operand = ifs.getCondition().getAChildExpr*() and
        (
          exists(DataFlow::CallExpr call | call = operand |
            call.getTarget().hasQualifiedName("strings", "HasSuffix") and
            sink.asExpr() = call.getArgument(0)
          )
          or
          exists(MapRead mapRead |
            operand = mapRead.asExpr() and
            sink = mapRead.getIndex().getAPredecessor*()
          )
          or
          exists(EqlExpr comp |
            operand = comp and
            (
              sink.asExpr() = comp.getLeftOperand() and
              not comp.getRightOperand().(StringLit).getStringValue() = ""
              or
              sink.asExpr() = comp.getRightOperand() and
              not comp.getLeftOperand().(StringLit).getStringValue() = ""
            )
          )
        )
      )
    |
      cgn.getCondition() = ifs.getCondition()
    )
  }
}

/**
 * Tracks taint flow for reasoning about when a `ActiveThreatModelSource` flows
 * somewhere.
 */
module FromUntrustedFlow = TaintTracking::Global<FromUntrustedConfig>;

/**
 * Holds if the provided `allowOriginHW` is also destination of a `ActiveThreatModelSource`.
 */
predicate flowsToGuardedByCheckOnUntrusted(DataFlow::ExprNode allowOriginHW) {
  exists(DataFlow::Node sink, ControlFlow::ConditionGuardNode cgn |
    FromUntrustedFlow::flowTo(sink) and FromUntrustedConfig::isSinkCgn(sink, cgn)
  |
    cgn.dominates(allowOriginHW.getBasicBlock())
  )
}

/** Holds if `node` is only reached when an `AllowedFlag` (for example, a debug flag) is checked. */
predicate isGuardedByAllowedFlag(DataFlow::Node node) {
  exists(ControlFlow::ConditionGuardNode cgn |
    cgn.ensures(any(AllowedFlag f).getAFlag().getANode(), _)
  |
    cgn.dominates(node.getBasicBlock())
  )
}

/**
 * Holds if `allowOriginHW` is reported by the experimental `go/cors-misconfiguration` query,
 * with the given `message`.
 */
predicate isReportedByCorsMisconfiguration(DataFlow::ExprNode allowOriginHW, string message) {
  allowCredentialsIsSetToTrue(allowOriginHW) and
  (
    flowsFromUntrustedToAllowOrigin(allowOriginHW, message)
    or
    allowOriginIsNull(allowOriginHW, message)
  ) and
  not flowsToGuardedByCheckOnUntrusted(allowOriginHW)
}

/*
 * Extensions: wildcard origins combined with credentials or state-changing methods.
 */

/** Holds if `origin` allows any origin, for example `*` or `https://*`. */
bindingset[origin]
predicate isWildcardOrigin(string origin) { origin.regexpMatch("(https?://)?\\*") }

/**
 * Holds if `methods` names a state-changing method that requires a CORS preflight request
 * (`PUT`, `PATCH` or `DELETE`).
 */
bindingset[methods]
predicate allowsStateChangingMethod(string methods) {
  methods.regexpMatch("(?i).*\\b(put|patch|delete)\\b.*")
}

/** Gets the message for a wildcard `origin` combined with `risk`. */
bindingset[origin, risk]
string wildcardMessage(string origin, string risk) {
  result = headerAllowOrigin() + " header is set to `" + origin + "`, and " + risk
}

/** Gets a description of the risk associated with a wildcard origin. */
string wildcardRisk(boolean credentials) {
  credentials = true and result = headerAllowCredentials() + " is set to `true`"
  or
  credentials = false and result = "state-changing methods (PUT, PATCH or DELETE) are allowed"
}

/** An `Access-Control-Allow-Methods` header write. */
class AllowMethodsHeaderWrite extends Http::HeaderWrite {
  AllowMethodsHeaderWrite() { this.getHeaderName() = "access-control-allow-methods" }
}

/**
 * Holds if header writes `a` and `b` use the same response writer and may both be executed
 * when handling a single request, that is, they are not on mutually exclusive branches.
 */
predicate onSameResponse(Http::HeaderWrite a, Http::HeaderWrite b) {
  a.getResponseWriter() = b.getResponseWriter() and
  (
    a.getRoot() != b.getRoot()
    or
    a.getBasicBlock().getASuccessor*() = b.getBasicBlock()
    or
    b.getBasicBlock().getASuccessor*() = a.getBasicBlock()
  )
}

/**
 * Holds if `hw` sets the `Access-Control-Allow-Origin` header to a wildcard on a response that
 * also allows credentials or state-changing methods.
 */
predicate wildcardOriginHeaderWrite(AllowOriginHeaderWrite hw, string message) {
  exists(string origin, boolean credentials |
    origin = hw.getHeaderValue() and
    isWildcardOrigin(origin) and
    (
      if
        exists(AllowCredentialsHeaderWrite c |
          c.getHeaderValue().toLowerCase() = "true" and
          onSameResponse(c, hw)
        )
      then credentials = true
      else (
        credentials = false and
        exists(AllowMethodsHeaderWrite m |
          allowsStateChangingMethod(m.getHeaderValue()) and
          onSameResponse(m, hw)
        )
      )
    ) and
    message = wildcardMessage(origin, wildcardRisk(credentials))
  )
}

/**
 * Holds if field `fieldName` of type `pkg.tp` is a CORS middleware configuration field of the
 * given `kind`: `origins`, `allOrigins`, `methods`, `credentials` or `originFunc`.
 */
predicate corsConfigField(string pkg, string tp, string kind, string fieldName) {
  pkg = package("github.com/labstack/echo", "middleware") and
  tp = "CORSConfig" and
  (
    kind = "origins" and fieldName = "AllowOrigins"
    or
    kind = "methods" and fieldName = "AllowMethods"
    or
    kind = "credentials" and fieldName = "AllowCredentials"
  )
  or
  pkg = package("github.com/gin-contrib/cors", "") and
  tp = "Config" and
  (
    kind = "origins" and fieldName = "AllowOrigins"
    or
    kind = "allOrigins" and fieldName = "AllowAllOrigins"
    or
    kind = "methods" and fieldName = "AllowMethods"
    or
    kind = "credentials" and fieldName = "AllowCredentials"
  )
  or
  pkg = package(["github.com/rs/cors", "github.com/go-chi/cors"], "") and
  tp = "Options" and
  (
    kind = "origins" and fieldName = "AllowedOrigins"
    or
    kind = "methods" and fieldName = "AllowedMethods"
    or
    kind = "credentials" and fieldName = "AllowCredentials"
  )
  or
  pkg = package("github.com/rs/cors", "") and
  tp = "Options" and
  kind = "originFunc" and
  (
    fieldName = "AllowOriginFunc"
    or
    fieldName = "AllowOriginRequestFunc"
    or
    fieldName = "AllowOriginVaryRequestFunc"
  )
  or
  pkg = package("github.com/go-chi/cors", "") and
  tp = "Options" and
  kind = "originFunc" and
  fieldName = "AllowOriginFunc"
}

/** A write to a field of a CORS middleware configuration struct. */
class CorsConfigFieldWrite extends DataFlow::Node {
  string kind;
  DataFlow::Node base;

  CorsConfigFieldWrite() {
    exists(Write w, Field f, string pkg, string tp, string fieldName |
      corsConfigField(pkg, tp, kind, fieldName) and
      f.hasQualifiedName(pkg, tp, fieldName) and
      w.writesFieldPreUpdate(base, f, this)
    )
  }

  /** Gets the kind of this field write (`origins`, `allOrigins`, `methods` or `credentials`). */
  string getKind() { result = kind }

  /** Gets the configuration struct written by this field write. */
  DataFlow::Node getBase() { result = base }

  /** Gets a string element of the slice literal written to this field. */
  string getAStringElement() { result = this.asExpr().(SliceLit).getAnElement().getStringValue() }

  /** Holds if `true` is written to this field. */
  predicate isTrue() { this.asExpr().getBoolValue() = true }

  /** Gets the SSA definition of the configuration struct written by this field write. */
  SsaDefinition getConfigDefinition() {
    exists(SsaVariable v | result = v.getDefinition() |
      v.getDefinition().(SsaExplicitDefinition).getRhs() = base.asInstruction() or
      v.getAUse() = base.asInstruction()
    )
  }

  /** Holds if these writes target a compatible path for the same configuration value. */
  predicate sameConfig(CorsConfigFieldWrite other) {
    (
      base = other.getBase() or
      this.getConfigDefinition() = other.getConfigDefinition()
    ) and
    (
      this.getBasicBlock() = other.getBasicBlock() or
      this.getBasicBlock().getASuccessor*() = other.getBasicBlock() or
      other.getBasicBlock().getASuccessor*() = this.getBasicBlock()
    )
  }
}

/**
 * Holds if `w` configures CORS middleware to allow any origin, and the same configuration also
 * allows credentials or explicitly allows state-changing methods.
 */
predicate wildcardOriginConfigWrite(CorsConfigFieldWrite w, string message) {
  exists(string origin, boolean credentials |
    (
      w.getKind() = "origins" and
      origin = min(string o | o = w.getAStringElement() and isWildcardOrigin(o))
      or
      w.getKind() = "allOrigins" and w.isTrue() and origin = "*"
    ) and
    not exists(CorsConfigFieldWrite callback |
      callback.getKind() = "originFunc" and
      callback.sameConfig(w)
    ) and
    (
      if
        exists(CorsConfigFieldWrite c |
          c.getKind() = "credentials" and c.isTrue() and c.sameConfig(w)
        )
      then credentials = true
      else (
        credentials = false and
        exists(CorsConfigFieldWrite m |
          m.getKind() = "methods" and
          allowsStateChangingMethod(m.getAStringElement()) and
          m.sameConfig(w)
        )
      )
    ) and
    message = wildcardMessage(origin, wildcardRisk(credentials))
  )
}

from DataFlow::Node allowOrigin, string message
where
  (
    isReportedByCorsMisconfiguration(allowOrigin, message)
    or
    wildcardOriginHeaderWrite(allowOrigin, message)
    or
    wildcardOriginConfigWrite(allowOrigin, message)
  ) and
  not isGuardedByAllowedFlag(allowOrigin)
select allowOrigin, message
