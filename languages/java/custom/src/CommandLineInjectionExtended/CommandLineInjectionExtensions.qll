/**
 * Provides the taint-tracking configuration for `java/command-line-injection-extended`.
 *
 * It reuses the sources, sinks, barriers and additional taint steps of
 * `java/command-line-injection` and adds:
 * - fields read in a custom `readObject(ObjectInputStream)` method of a `Serializable`
 *   class, whose values come from the deserialized stream, as sources;
 * - a taint step for Kotlin `toString()` calls on Android `Editable` values, which the
 *   Kotlin extractor binds to `Object.toString` through an implicit cast.
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.CommandLineQuery

/** A custom `readObject(ObjectInputStream)` deserialization method of a `Serializable` class. */
class CustomReadObjectMethod extends Method {
  CustomReadObjectMethod() {
    this.hasName("readObject") and
    this.getNumberOfParameters() = 1 and
    this.getParameterType(0).(RefType).hasQualifiedName("java.io", "ObjectInputStream") and
    this.getDeclaringType().getASourceSupertype+().hasQualifiedName("java.io", "Serializable")
  }
}

/**
 * A read of a serialized (non-static, non-transient) field of the current object inside a
 * custom `readObject` method. Its value is restored from the deserialized stream, so it is
 * controlled by whoever supplied the serialized data.
 */
class DeserializedFieldRead extends DataFlow::Node {
  DeserializedFieldRead() {
    exists(FieldRead fr, Field f |
      fr = this.asExpr() and
      f = fr.getField() and
      fr.isOwnFieldAccess() and
      fr.getEnclosingCallable() instanceof CustomReadObjectMethod and
      not f.isStatic() and
      not f.isTransient()
    )
  }
}

/**
 * Holds if `n1` is the receiver of a Kotlin `toString()` call on an Android `Editable` and
 * `n2` is the call. Kotlin binds `Editable.toString()` to `Object.toString` through an
 * implicit cast, so the Java-only `Editable` taint step does not apply.
 */
predicate kotlinEditableToStringStep(DataFlow::Node n1, DataFlow::Node n2) {
  exists(MethodCall ma, ImplicitCastExpr cast |
    ma.getMethod().hasName("toString") and
    ma.getMethod().getNumberOfParameters() = 0 and
    cast = ma.getQualifier() and
    cast.getExpr()
        .getType()
        .(RefType)
        .getASourceSupertype*()
        .hasQualifiedName("android.text", "Editable") and
    n1.asExpr() = cast and
    n2.asExpr() = ma
  )
}

/** Gets a description of the source `n` for the alert message. */
string sourceDescription(DataFlow::Node n) {
  if n instanceof DeserializedFieldRead
  then result = "deserialized field"
  else result = "user-provided value"
}

/** Configuration for `java/command-line-injection-extended`. */
module CommandLineInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    InputToArgumentToExecFlowConfig::isSource(src) or src instanceof DeserializedFieldRead
  }

  predicate isSink(DataFlow::Node sink) { InputToArgumentToExecFlowConfig::isSink(sink) }

  predicate isBarrier(DataFlow::Node node) { InputToArgumentToExecFlowConfig::isBarrier(node) }

  // Report each sink once, from the field read closest to it, rather than from every
  // earlier read of the same field.
  predicate isBarrierIn(DataFlow::Node node) { node instanceof DeserializedFieldRead }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    InputToArgumentToExecFlowConfig::isAdditionalFlowStep(n1, n2)
    or
    kotlinEditableToStringStep(n1, n2)
  }
}

/** Taint-tracking flow for `java/command-line-injection-extended`. */
module CommandLineInjectionExtendedFlow = TaintTracking::Global<CommandLineInjectionExtendedConfig>;
