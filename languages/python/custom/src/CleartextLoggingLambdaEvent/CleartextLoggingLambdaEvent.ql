/**
 * @name Clear-text logging of sensitive AWS Lambda event
 * @description Logging an entire AWS Lambda event that carries payment card or
 *              other sensitive data exposes that data in the logs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/clear-text-logging-sensitive-lambda-event
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 *       external/cwe/cwe-532
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CleartextLoggingCustomizations
private import codeql.concepts.internal.SensitiveDataHeuristics

/** Holds if `key` names payment card data (e.g. `billing`, `card_number`, `cvv`). */
bindingset[key]
predicate isPaymentKey(string key) {
  key.regexpMatch("(?i)(billing|payment|credit.?card|card|cc.?num|ccn|cvv|cvc|card.?(number|num|no)|pan)(.?(info|details|data))?")
}

/** Holds if `key` names sensitive data, classified as `classification`. */
bindingset[key]
predicate isSensitiveKey(string key, string classification) {
  isPaymentKey(key) and classification = SensitiveDataClassification::private()
  or
  key.regexpMatch(HeuristicNames::maybeSensitiveRegexp(classification)) and
  not key.regexpMatch(HeuristicNames::notSensitiveRegexp()) and
  not classification in [
      SensitiveDataClassification::id(), SensitiveDataClassification::certificate()
    ]
}

/** Gets a string literal key used to read from a local alias of `event` (`event[k]` or `event.get(k)`). */
string getAReadKey(DataFlow::ParameterNode event, DataFlow::Node read) {
  exists(DataFlow::Node obj | DataFlow::localFlow(event, obj) |
    exists(SubscriptNode sub |
      read.asCfgNode() = sub and
      sub.getObject() = obj.asCfgNode() and
      result = sub.getIndex().getNode().(StringLiteral).getText()
    )
    or
    exists(DataFlow::MethodCallNode call |
      read = call and
      call.calls(obj, "get") and
      result = call.getArg(0).asExpr().(StringLiteral).getText()
    )
  )
}

/**
 * The `event` parameter of an AWS Lambda handler, i.e. a function `f(event, context)`,
 * where the handler reads a payment or otherwise sensitive key from the event.
 */
class SensitiveLambdaEvent extends DataFlow::ParameterNode {
  string classification;

  SensitiveLambdaEvent() {
    exists(Function f |
      f.getPositionalParameterCount() = 2 and
      f.getArg(1).(Name).getId() = "context" and
      this.getParameter() = f.getArg(0)
    ) and
    isSensitiveKey(getAReadKey(this, _), classification)
  }

  string getClassification() { result = classification }
}

module CleartextLoggingLambdaEventConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveLambdaEvent }

  predicate isSink(DataFlow::Node sink) { sink instanceof CleartextLogging::Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CleartextLogging::Sanitizer
    or
    // Reading a non-sensitive key (e.g. a correlation ID) from the event is safe to log.
    exists(string key | key = getAReadKey(_, node) and not isSensitiveKey(key, _))
  }
}

module CleartextLoggingLambdaEventFlow = TaintTracking::Global<CleartextLoggingLambdaEventConfig>;

import CleartextLoggingLambdaEventFlow::PathGraph

from
  CleartextLoggingLambdaEventFlow::PathNode source, CleartextLoggingLambdaEventFlow::PathNode sink
where CleartextLoggingLambdaEventFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This expression logs $@ as clear text.", source.getNode(),
  "an AWS Lambda event containing sensitive data (" +
    source.getNode().(SensitiveLambdaEvent).getClassification() + ")"
