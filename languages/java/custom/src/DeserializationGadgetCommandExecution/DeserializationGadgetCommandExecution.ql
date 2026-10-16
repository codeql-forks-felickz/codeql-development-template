/**
 * @name Command execution from a deserialization callback
 * @description A serializable class that runs an external command built from its own
 *              deserialized state in `readObject`, `readResolve` or `readExternal` is a
 *              ready-made gadget: deserializing untrusted data executes attacker-chosen commands.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/deserialization-gadget-command-execution
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.security.CommandLineQuery
import semmle.code.java.security.ExternalProcess
import semmle.code.java.dataflow.TaintTracking

/**
 * A method that the Java serialization runtime calls while reconstructing an object
 * from a stream.
 */
class DeserializationCallback extends Method {
  DeserializationCallback() {
    this.getDeclaringType().getASourceSupertype*() instanceof TypeSerializable and
    (
      this.hasName("readObject") and
      this.getNumberOfParameters() = 1 and
      this.getParameterType(0) instanceof TypeObjectInputStream
      or
      this.hasName("readObjectNoData") and this.getNumberOfParameters() = 0
      or
      this.hasName("readResolve") and this.getNumberOfParameters() = 0
      or
      this.hasName("readExternal") and
      this.getNumberOfParameters() = 1 and
      this.getParameterType(0).(RefType).hasQualifiedName("java.io", "ObjectInput")
    )
  }
}

/**
 * Attacker-controlled state available in a deserialization callback: a read of a
 * serialized (non-static, non-transient) field of the object being deserialized, or a
 * value read from the input stream.
 */
class DeserializedStateSource extends DataFlow::Node {
  DeserializedStateSource() {
    exists(DeserializationCallback m, FieldRead fr, Field f |
      fr = this.asExpr() and
      fr.getEnclosingCallable() = m and
      f = fr.getField() and
      f.getDeclaringType() = m.getDeclaringType() and
      fr.isOwnFieldAccess() and
      not f.isStatic() and
      not f.isTransient()
    )
    or
    exists(DeserializationCallback m, MethodCall mc |
      mc = this.asExpr() and
      mc.getEnclosingCallable() = m and
      mc.getQualifier() = m.getParameter(0).getAnAccess() and
      mc.getMethod().getName().matches("read%") and
      not mc.getMethod().hasName("defaultReadObject")
    )
  }
}

module DeserializationGadgetCommandConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DeserializedStateSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjectionSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CommandInjectionSanitizer }

  // Report each sink once, from the closest read of deserialized state.
  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    any(CommandInjectionAdditionalTaintStep s).step(n1, n2)
  }
}

module DeserializationGadgetCommandFlow = TaintTracking::Global<DeserializationGadgetCommandConfig>;

import DeserializationGadgetCommandFlow::PathGraph

from
  DeserializationGadgetCommandFlow::PathNode source,
  DeserializationGadgetCommandFlow::PathNode sink, Expr execArg
where
  DeserializationGadgetCommandFlow::flowPath(source, sink) and
  argumentToExec(execArg, sink.getNode())
select execArg, source, sink,
  "This command line depends on $@ restored during deserialization, so deserializing untrusted data can run arbitrary commands.",
  source.getNode(), "object state"
