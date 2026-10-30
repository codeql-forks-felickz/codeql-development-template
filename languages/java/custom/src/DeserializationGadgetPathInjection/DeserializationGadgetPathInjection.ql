/**
 * @name Deserialization callback uses deserialized state as a file path
 * @description A `readObject`, `readExternal` or `readResolve` callback that builds a file
 *              path from deserialized fields or stream data turns the class into a gadget:
 *              anyone who can supply a serialized stream can make it read or write
 *              arbitrary files.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id java/deserialization-gadget-path-injection
 * @tags security
 *       external/cwe/cwe-502
 *       external/cwe/cwe-022
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.TaintedPathQuery
import semmle.code.java.security.PathSanitizer
private import semmle.code.java.security.Sanitizers
import DeserializationGadgetPathFlow::PathGraph

/**
 * A deserialization callback invoked by the Java serialization runtime on attacker-supplied
 * stream data.
 */
class DeserializationCallback extends Method {
  DeserializationCallback() {
    this.getDeclaringType().getAnAncestor() instanceof TypeSerializable and
    (
      this.hasName("readObject") and
      this.getNumberOfParameters() = 1 and
      this.getParameterType(0) instanceof TypeObjectInputStream and
      this.isPrivate() and
      not this.isStatic() and
      this.getReturnType() instanceof VoidType
      or
      this.hasName("readExternal") and
      this.getNumberOfParameters() = 1 and
      this.getParameterType(0) instanceof TypeObjectInput and
      this.getDeclaringType().getAnAncestor().hasQualifiedName("java.io", "Externalizable") and
      this.isPublic() and
      not this.isStatic() and
      this.getReturnType() instanceof VoidType
      or
      this.hasName("readResolve") and
      this.getNumberOfParameters() = 0 and
      not this.isStatic() and
      not this.getReturnType() instanceof PrimitiveType and
      not this.getReturnType() instanceof VoidType
    )
  }
}

/** A field whose value is restored from the serialized stream. */
class DeserializedField extends Field {
  DeserializedField() {
    not this.isStatic() and
    not this.isTransient() and
    this.getDeclaringType().getAnAncestor() instanceof TypeSerializable
  }
}

/**
 * Deserialized state observed inside a deserialization callback: a read of a
 * non-transient instance field of `this`, or a value read from the stream parameter.
 */
class DeserializedStateSource extends DataFlow::Node {
  DeserializedStateSource() {
    exists(DeserializationCallback cb, FieldRead fr |
      fr = this.asExpr() and
      fr.getEnclosingCallable() = cb and
      fr.getField() instanceof DeserializedField and
      fr.isOwnFieldAccess() and
      not exists(AssignExpr assignment, FieldWrite fw |
        assignment.getDest() = fw and
        fw.getField() = fr.getField() and
        assignment.getEnclosingCallable() = cb and
        fw.isOwnFieldAccess() and
        fr != assignment.getSource() and
        DataFlow::localFlow(DataFlow::exprNode(assignment.getSource()), DataFlow::exprNode(fr))
      )
    )
    or
    exists(DeserializationCallback cb, MethodCall mc |
      mc = this.asExpr() and
      mc.getEnclosingCallable() = cb and
      DataFlow::localFlow(DataFlow::exprNode(cb.getParameter(0).getAnAccess()),
        DataFlow::exprNode(mc.getQualifier())) and
      mc.getMethod().getName().matches("read%") and
      not mc.getMethod().hasName("defaultReadObject")
    )
  }
}

module DeserializationGadgetPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DeserializedStateSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof TaintedPathSink }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof SimpleTypeSanitizer or
    node instanceof PathInjectionSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    any(TaintedPathAdditionalTaintStep s).step(n1, n2)
  }
}

module DeserializationGadgetPathFlow = TaintTracking::Global<DeserializationGadgetPathConfig>;

from DeserializationGadgetPathFlow::PathNode source, DeserializationGadgetPathFlow::PathNode sink
where DeserializationGadgetPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This path depends on $@ restored during deserialization, so a crafted serialized stream can choose which file is accessed.",
  source.getNode(), "state"
