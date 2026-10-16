/**
 * @name Security decision based on reverse DNS lookup
 * @description Host names obtained through a reverse DNS lookup are controlled by whoever
 *              controls the DNS records of the IP address and can be spoofed, so they must not
 *              be used to authenticate or authorize a client.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cs/reverse-dns-security-decision
 * @tags security
 *       external/cwe/cwe-350
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking

/** A reverse DNS lookup of an IP address. */
class ReverseDnsLookup extends DataFlow::ExprNode {
  ReverseDnsLookup() {
    exists(MethodCall mc, Method m |
      mc = this.getExpr() and
      m = mc.getTarget() and
      m.getDeclaringType().hasFullyQualifiedName("System.Net", "Dns")
    |
      m.hasName("GetHostByAddress")
      or
      m.hasName(["GetHostEntry", "GetHostEntryAsync"]) and
      m.getParameter(0).getType().(RefType).hasFullyQualifiedName("System.Net", "IPAddress")
    )
  }
}

/** A comparison whose result depends on `e`. */
predicate isComparisonOperand(Expr comparison, Expr e) {
  comparison.(EqualityOperation).getAnOperand() = e
  or
  exists(MethodCall mc | mc = comparison |
    mc.getTarget()
        .hasName([
            "Equals", "StartsWith", "EndsWith", "Contains", "Compare", "CompareOrdinal", "IsMatch"
          ]) and
    (e = mc.getQualifier() or e = mc.getAnArgument())
  )
}

/** Holds if the value of `comparison` is used to make a decision. */
predicate isDecision(Expr comparison) {
  exists(Expr cond | comparison = cond.getAChildExpr*() |
    cond = any(IfStmt s | not onlyRecordsHostName(s)).getCondition()
    or
    cond = any(ConditionalExpr c).getCondition()
    or
    cond = any(LoopStmt l).getCondition()
    or
    cond = any(ReturnStmt r).getExpr()
    or
    cond = any(Callable c).getExpressionBody()
  )
}

/** Holds if `call` writes information to a log or output, rather than taking an action. */
predicate isLoggingCall(MethodCall call) {
  call.getTarget().getName().regexpMatch("(?i).*(log|trace|debug|info|warn|write|print|audit).*")
}

/**
 * Holds if the only effect of the branch guarded by `s` is to record the resolved host name,
 * which is not a security decision.
 */
predicate onlyRecordsHostName(IfStmt s) {
  not exists(s.getElse()) and
  forex(Stmt st | st = s.getThen().(BlockStmt).getAStmt() or st = s.getThen().(ExprStmt) |
    exists(MethodCall mc | mc = st.(ExprStmt).getExpr() |
      isLoggingCall(mc) and
      mc.getAnArgument().getAChildExpr*().(PropertyAccess).getTarget().hasName("HostName")
    )
  )
}

/** A value that is compared in order to make a security decision. */
class DecisionSink extends DataFlow::ExprNode {
  DecisionSink() {
    exists(Expr comparison |
      isComparisonOperand(comparison, this.getExpr()) and
      isDecision(comparison)
    )
  }
}

module ReverseDnsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReverseDnsLookup }

  predicate isSink(DataFlow::Node sink) { sink instanceof DecisionSink }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof DecisionSink }
}

module ReverseDnsFlow = TaintTracking::Global<ReverseDnsConfig>;

import ReverseDnsFlow::PathGraph

from ReverseDnsFlow::PathNode source, ReverseDnsFlow::PathNode sink
where ReverseDnsFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This security decision depends on a host name from a $@, which can be spoofed.",
  source.getNode(), "reverse DNS lookup"
