/**
 * @name Predictable value used as a security token
 * @description Using a value derived from `System.Random` or from the system clock as a
 *              session identifier, token, captcha, one-time or approval code allows an
 *              attacker to predict or brute-force it.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id cs/weak-crypto-randomness
 * @tags security
 *       external/cwe/cwe-330
 *       external/cwe/cwe-338
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking

/**
 * Holds if the (lower-cased) identifier `name` looks like it holds a security token
 * such as a session identifier, a captcha, or a one-time code.
 */
bindingset[name]
predicate isSensitiveTokenName(string name) {
  exists(string n | n = name.toLowerCase() |
    n.regexpMatch(".*(session_?(id|key|token)|sessid|token|nonce|captcha|csrf|xsrf|secret|salt|" +
        "(verification|verify|approval|confirm|confirmation|reset|activation|auth|access|security|pin|recovery|otp)_?code).*")
    or
    n.regexpMatch("otp.*|.*otp")
  ) and
  not name.toLowerCase()
      .regexpMatch(".*(hash|encrypt|crypt|invalid|expir|time|date|created|issued|stamp|count|length|size|name|type|url|uri|path|header|timeout|duration|cancel|attempt|retry|index).*")
}

/** A predictable value: the output of `System.Random` or a reading of the system clock. */
class PredictableSource extends DataFlow::ExprNode {
  string kind;

  PredictableSource() {
    exists(MethodCall mc | mc = this.getExpr() |
      mc.getQualifier().getType().(RefType).hasFullyQualifiedName("System", "Random") and
      kind = "System.Random"
    )
    or
    exists(PropertyAccess pa | pa = this.getExpr() |
      pa.getTarget()
          .getDeclaringType()
          .hasFullyQualifiedName("System", ["DateTime", "DateTimeOffset"]) and
      pa.getTarget().hasName(["Now", "UtcNow", "Today"]) and
      kind = "the system clock"
      or
      pa.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Environment") and
      pa.getTarget().hasName(["TickCount", "TickCount64"]) and
      kind = "the system clock"
    )
    or
    exists(MethodCall mc | mc = this.getExpr() |
      mc.getTarget().getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "Stopwatch") and
      mc.getTarget().hasName("GetTimestamp") and
      kind = "the system clock"
    )
  }

  /** Gets a description of the kind of predictable value. */
  string getKind() { result = kind }
}

/** A cryptographically strong source of randomness. */
class SecureRandomSource extends DataFlow::ExprNode {
  SecureRandomSource() {
    exists(Call c | c = this.getExpr() |
      c.getTarget()
          .getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName("System.Security.Cryptography", "RandomNumberGenerator")
      or
      c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Guid") and
      c.getTarget().hasName("NewGuid")
    )
  }
}

/** Holds if `e` is a cookie (or cookie name) that identifies a session or authentication token. */
predicate isSensitiveCookie(Expr cookie) {
  exists(ObjectCreation oc |
    oc.getType()
        .(RefType)
        .hasFullyQualifiedName(["System.Web", "System.Net"], ["HttpCookie", "Cookie"]) and
    isSensitiveTokenName(oc.getArgument(0).(StringLiteral).getValue()) and
    DataFlow::localExprFlow(oc, cookie)
  )
  or
  exists(Variable v |
    cookie = v.getAnAccess() and
    v.getType()
        .(RefType)
        .hasFullyQualifiedName(["System.Web", "System.Net"], ["HttpCookie", "Cookie"]) and
    isSensitiveTokenName(v.getName())
  )
}

/** A value that is used as a security token, session identifier or one-time code. */
class SensitiveTokenSink extends DataFlow::ExprNode {
  SensitiveTokenSink() {
    exists(Expr e | e = this.getExpr() |
      // Assignment to a sensitively named variable, field or property
      exists(Assignable a | isSensitiveTokenName(a.getName()) |
        e = a.getAnAssignedValue()
        or
        exists(AssignOperation ao |
          ao.getRightOperand() = e and ao.getLeftOperand() = a.getAnAccess()
        )
      )
      or
      // Argument to a sensitively named parameter
      exists(Parameter p | isSensitiveTokenName(p.getName()) and e = p.getAnAssignedArgument())
      or
      // Value of a sensitive cookie: `new HttpCookie("SessionId", value)`
      exists(ObjectCreation oc |
        oc.getType()
            .(RefType)
            .hasFullyQualifiedName(["System.Web", "System.Net"], ["HttpCookie", "Cookie"]) and
        isSensitiveTokenName(oc.getArgument(0).(StringLiteral).getValue()) and
        e = oc.getArgument(1)
      )
      or
      // Value of a sensitive cookie: `cookie.Value = value`
      exists(AssignExpr ae, PropertyAccess pa |
        pa = ae.getLeftOperand() and
        pa.getTarget().hasName("Value") and
        isSensitiveCookie(pa.getQualifier()) and
        e = ae.getRightOperand()
      )
      or
      // ASP.NET Core: `Response.Cookies.Append("SessionId", value)`
      exists(MethodCall mc |
        mc.getTarget().hasName("Append") and
        mc.getTarget()
            .getDeclaringType()
            .getABaseType*()
            .hasFullyQualifiedName("Microsoft.AspNetCore.Http", "IResponseCookies") and
        isSensitiveTokenName(mc.getArgument(0).(StringLiteral).getValue()) and
        e = mc.getArgument(1)
      )
    )
  }
}

/** Holds if taint propagates from `pred` to `succ` through a value conversion or arithmetic. */
predicate predictableValueStep(DataFlow::Node pred, DataFlow::Node succ) {
  // `x.ToString(...)`
  exists(MethodCall mc |
    mc.getTarget().hasName("ToString") and
    pred.asExpr() = mc.getQualifier() and
    succ.asExpr() = mc
  )
  or
  // `DateTime.Now.Hour`, `DateTime.UtcNow.Ticks`, ...
  exists(PropertyAccess pa |
    pa.getTarget()
        .getDeclaringType()
        .hasFullyQualifiedName("System", ["DateTime", "DateTimeOffset", "TimeSpan"]) and
    pred.asExpr() = pa.getQualifier() and
    succ.asExpr() = pa
  )
  or
  // Arithmetic on predictable numbers keeps them predictable
  exists(BinaryArithmeticOperation op |
    not op.getType() instanceof StringType and
    pred.asExpr() = op.getAnOperand() and
    succ.asExpr() = op
  )
}

module SecureRandomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SecureRandomSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SensitiveTokenSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    predictableValueStep(pred, succ)
  }
}

module SecureRandomFlow = TaintTracking::Global<SecureRandomConfig>;

module WeakCryptoRandomnessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof PredictableSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SensitiveTokenSink and
    // A value that also mixes in cryptographically strong randomness is not predictable.
    not SecureRandomFlow::flowTo(sink)
  }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof SensitiveTokenSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    predictableValueStep(pred, succ)
  }
}

module WeakCryptoRandomnessFlow = TaintTracking::Global<WeakCryptoRandomnessConfig>;

import WeakCryptoRandomnessFlow::PathGraph

from
  WeakCryptoRandomnessFlow::PathNode source, WeakCryptoRandomnessFlow::PathNode sink,
  PredictableSource src
where
  WeakCryptoRandomnessFlow::flowPath(source, sink) and
  src = source.getNode()
select sink.getNode(), source, sink,
  "This security-sensitive value is derived from a predictable value from $@.", src, src.getKind()
