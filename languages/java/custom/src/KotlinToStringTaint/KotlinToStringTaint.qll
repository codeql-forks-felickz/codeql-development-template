/**
 * Provides a taint step for Kotlin `toString()` calls on receivers whose Java
 * `toString()` is modeled as taint-preserving.
 *
 * The Kotlin extractor resolves `x.toString()` to `kotlin.Any.toString()`, which is
 * extracted as `java.lang.Object.toString()` with the receiver wrapped in an implicit
 * cast to `Any`. As a result, the type-specific models for `CharSequence.toString()`
 * (which covers `android.text.Editable`) and `android.net.Uri.toString()`, as well as
 * the `android.text.Editable` taint step in `semmle.code.java.frameworks.android.Widget`,
 * do not apply to Kotlin code and taint is lost.
 */

import java
private import semmle.code.java.dataflow.DataFlow

/**
 * A type whose `toString()` method is modeled as propagating taint from the receiver
 * to the result for Java code.
 */
private class TaintPreservingToStringType extends RefType {
  TaintPreservingToStringType() {
    this.getASourceSupertype*().hasQualifiedName("java.lang", "CharSequence")
    or
    this.getASourceSupertype*().hasQualifiedName("android.net", "Uri")
  }
}

/**
 * Holds if `n1` is the receiver and `n2` the result of a Kotlin `toString()` call whose
 * receiver (ignoring any implicit cast to `Any`) has a `TaintPreservingToStringType`.
 */
predicate kotlinToStringTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
  exists(MethodCall ma, Expr receiver |
    ma.getFile().isKotlinSourceFile() and
    ma.getMethod().hasName("toString") and
    ma.getMethod().hasNoParameters() and
    ma.getMethod().getDeclaringType() instanceof TypeObject and
    receiver = ma.getQualifier() and
    receiver.getUnderlyingExpr().getType() instanceof TaintPreservingToStringType and
    n1.asExpr() = receiver and
    n2.asExpr() = ma
  )
}
