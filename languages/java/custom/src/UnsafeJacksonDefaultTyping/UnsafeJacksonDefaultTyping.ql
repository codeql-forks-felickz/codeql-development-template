/**
 * @name Deserialization of user-controlled data with permissive Jackson default typing
 * @description Deserializing user-controlled data with a Jackson `ObjectMapper` whose default
 *              typing is activated with a permissive type validator (such as
 *              `LaissezFaireSubTypeValidator`) lets the payload choose arbitrary classes to
 *              instantiate, which may allow attackers to execute arbitrary code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/unsafe-deserialization-jackson-default-typing
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.Jackson
import semmle.code.java.security.UnsafeDeserializationQuery

/** The Jackson `LaissezFaireSubTypeValidator` type, which allows any subtype to be instantiated. */
class LaissezFaireSubTypeValidator extends RefType {
  LaissezFaireSubTypeValidator() {
    this.hasQualifiedName("com.fasterxml.jackson.databind.jsontype.impl",
      "LaissezFaireSubTypeValidator")
  }
}

/**
 * A call that enables Jackson default typing on an `ObjectMapper` without restricting the types
 * that may be instantiated, and that is not already recognized by `java/unsafe-deserialization`
 * (which only recognizes calls named exactly `enableDefaultTyping`). That is, either:
 * - a call to `activateDefaultTyping` or `activateDefaultTypingAsProperty` with a
 *   `LaissezFaireSubTypeValidator`, or
 * - a call to the deprecated `enableDefaultTypingAsProperty`, which uses no type validator.
 */
class PermissiveJacksonDefaultTyping extends MethodCall {
  PermissiveJacksonDefaultTyping() {
    this.getMethod()
        .getDeclaringType()
        .getAnAncestor()
        .hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    (
      this.getMethod().hasName(["activateDefaultTyping", "activateDefaultTypingAsProperty"]) and
      exists(Expr validator |
        validator.getType() instanceof LaissezFaireSubTypeValidator and
        DataFlow::localExprFlow(validator, this.getArgument(0))
      )
      or
      this.getMethod().hasName("enableDefaultTypingAsProperty")
    )
  }
}

/**
 * Tracks flow from an `ObjectMapper` configured with permissive default typing to the qualifier
 * of a subsequent Jackson deserialization method call.
 */
module PermissiveJacksonDefaultTypingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src.asExpr() = any(PermissiveJacksonDefaultTyping ma).getQualifier()
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof ObjectMapperReadQualifier }
}

module PermissiveJacksonDefaultTypingFlow = DataFlow::Global<PermissiveJacksonDefaultTypingConfig>;

/**
 * The data argument of a Jackson deserialization method call on an `ObjectMapper` configured with
 * permissive default typing, which is not already a sink of `java/unsafe-deserialization`.
 */
class UnsafeJacksonDefaultTypingSink extends DataFlow::ExprNode {
  MethodCall mc;

  UnsafeJacksonDefaultTypingSink() {
    mc.getMethod() instanceof ObjectMapperReadMethod and
    this.getExpr() = mc.getArgument(0) and
    PermissiveJacksonDefaultTypingFlow::flowToExpr(mc.getQualifier()) and
    not SafeObjectMapperFlow::flowToExpr(mc.getQualifier()) and
    not this instanceof UnsafeDeserializationSink
  }

  /** Gets the call that triggers unsafe deserialization. */
  MethodCall getMethodCall() { result = mc }
}

/** Tracks flow from user-controlled data to a permissively configured Jackson deserializer. */
module UnsafeJacksonDefaultTypingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeJacksonDefaultTypingSink }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    createJacksonJsonParserStep(pred, succ) or
    createJacksonTreeNodeStep(pred, succ)
  }
}

module UnsafeJacksonDefaultTypingFlow = TaintTracking::Global<UnsafeJacksonDefaultTypingConfig>;

import UnsafeJacksonDefaultTypingFlow::PathGraph

from UnsafeJacksonDefaultTypingFlow::PathNode source, UnsafeJacksonDefaultTypingFlow::PathNode sink
where UnsafeJacksonDefaultTypingFlow::flowPath(source, sink)
select sink.getNode().(UnsafeJacksonDefaultTypingSink).getMethodCall(), source, sink,
  "Unsafe deserialization with permissive Jackson default typing depends on a $@.",
  source.getNode(), "user-provided value"
