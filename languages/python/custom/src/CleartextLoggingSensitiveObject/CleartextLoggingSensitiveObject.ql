/**
 * @name Clear-text logging of an object containing sensitive data
 * @description Logging a whole object (such as an AWS Lambda event or a parsed
 *              request body) that carries payment card or other sensitive data
 *              exposes that data in the logs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/clear-text-logging-sensitive-object
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

/** Holds if `p` is the `event` parameter of an AWS Lambda handler `f(event, context)`. */
predicate isLambdaEvent(DataFlow::ParameterNode p) {
  exists(Function f |
    f.getPositionalParameterCount() = 2 and
    f.getArg(1).(Name).getId() = "context" and
    p.getParameter() = f.getArg(0)
  )
}

/**
 * Holds if `n` may be a container of keyed data: an AWS Lambda `event` parameter,
 * or the result of a call (e.g. `request.get_json()` or `json.loads(...)`).
 */
predicate isCandidateContainer(DataFlow::Node n) {
  isLambdaEvent(n)
  or
  n instanceof DataFlow::CallCfgNode
}

/**
 * Gets a string literal key used to read from a local alias of `container`,
 * via `container[k]` or `container.get(k)`.
 */
string getAReadKey(DataFlow::Node container, DataFlow::Node read) {
  exists(DataFlow::Node obj | DataFlow::localFlow(container, obj) |
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
 * A candidate container (AWS Lambda event or call result) from which a payment
 * or otherwise sensitive key is read, so the whole object holds sensitive data.
 */
class SensitiveObject extends DataFlow::Node {
  string classification;

  SensitiveObject() {
    isCandidateContainer(this) and isSensitiveKey(getAReadKey(this, _), classification)
  }

  string getClassification() { result = classification }

  /** Gets a description of this object for alert messages. */
  string getDescription() {
    if isLambdaEvent(this) then result = "an AWS Lambda event" else result = "an object"
  }
}

module CleartextLoggingSensitiveObjectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof SensitiveObject }

  predicate isSink(DataFlow::Node sink) { sink instanceof CleartextLogging::Sink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof CleartextLogging::Sanitizer
    or
    // Reading a non-sensitive key (e.g. a correlation ID) from the object is safe to log.
    exists(string key |
      key = getAReadKey(_, node) and not isSensitiveKey(key, _) and
      not node instanceof SensitiveObject
    ) and
    not exists(DataFlow::MethodCallNode call |
      node = call and call.calls(_, "get") and
      TaintTracking::localTaint(call.getObject(), call.getArg(1))
    )
  }
}

module CleartextLoggingSensitiveObjectFlow =
  TaintTracking::Global<CleartextLoggingSensitiveObjectConfig>;

import CleartextLoggingSensitiveObjectFlow::PathGraph

from
  CleartextLoggingSensitiveObjectFlow::PathNode source,
  CleartextLoggingSensitiveObjectFlow::PathNode sink, SensitiveObject obj
where
  CleartextLoggingSensitiveObjectFlow::flowPath(source, sink) and
  obj = source.getNode()
select sink.getNode(), source, sink, "This expression logs $@ as clear text.", obj,
  obj.getDescription() + " containing sensitive data (" +
    concat(string c | c = obj.getClassification() | c, ", ") + ")"
