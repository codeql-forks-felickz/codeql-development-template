/**
 * Provides a taint-tracking configuration for reasoning about uncontrolled data in path
 * expressions. It reuses the sources, sinks and sanitizers of `cs/path-injection`, but does
 * not treat null checks, NUL-character checks or checks on a single character or the length
 * of a path as path validation, does not treat `char` values as sanitized, and also includes
 * `path-injection` sinks from models-as-data.
 */

import csharp
private import semmle.code.csharp.controlflow.Guards
private import semmle.code.csharp.dataflow.internal.ExternalFlow
private import semmle.code.csharp.frameworks.system.IO
private import semmle.code.csharp.security.Sanitizers
private import semmle.code.csharp.security.dataflow.TaintedPathQuery as TP

/**
 * Holds if `g` guards a data flow node with boolean value, where `sub` is the
 * sub-expression of `g` that is structurally equal to the guarded expression.
 */
private predicate booleanGuardFor(Guard g, Expr sub) {
  exists(GuardedDataFlowNode n, GuardValue v |
    g = n.getAGuard(sub, v) and
    exists(v.asBooleanValue())
  )
}

/** Gets `g`, or an operand (transitively) of `g` when it is a logical operation. */
private Expr getALogicalOperand(Guard g) {
  result = g
  or
  result = getALogicalOperand(g).(LogicalOperation).getAnOperand()
}

/**
 * Holds if the check `op` on `sub` (a sub-expression of `op`) is insufficient to prevent path
 * tampering of `sub`.
 */
bindingset[op, sub]
pragma[inline_late]
private predicate isWeakCheck(Expr op, Expr sub) {
  // The weak guards from `cs/path-injection`.
  exists(Method m | op.(MethodCall).getTarget() = m |
    m.getName() = ["StartsWith", "EndsWith", "IsNullOrEmpty", "IsNullOrWhitespace"] or
    m = any(SystemIOFileClass f).getAMethod("Exists") or
    m = any(SystemIODirectoryClass f).getAMethod("Exists")
  )
  or
  op.(Guard).controlsNode(_, _, any(GuardValue nv | nv.isNullness(_)))
  or
  // `sub == null`, `sub != null`, `sub is null` and `sub is not null` only check for nullness.
  op.(EqualityOperation).getAnOperand() = sub and
  op.(EqualityOperation).getAnOperand() instanceof NullLiteral
  or
  op.(IsExpr).getExpr() = sub and
  (
    op.(IsExpr).getPattern() instanceof NullLiteral or
    op.(IsExpr).getPattern().(NotPatternExpr).getPattern() instanceof NullLiteral
  )
  or
  // Comparing a character with the NUL character (e.g. `path[i] != 0` in a copy loop) does
  // not validate it.
  exists(Expr other |
    op.(EqualityOperation).getAnOperand().stripImplicit() = sub and
    other = op.(EqualityOperation).getAnOperand().stripImplicit() and
    other != sub and
    sub.getType() instanceof CharType
  |
    other.(IntegerLiteral).getValue() = "0" or
    other.(CharLiteral).getValue().codePointAt(0) = 0
  )
  or
  // Inspecting a single character, or the length, of a path does not validate the path.
  sub = any(ElementAccess ea).getQualifier()
  or
  sub = any(PropertyAccess pa | pa.getTarget().hasName("Length")).getQualifier()
}

/**
 * Holds if guard `g`, with `sub` being the sub-expression of `g` that is structurally equal to
 * the guarded expression, is insufficient to prevent path tampering of that expression.
 */
private predicate isWeakGuardFor(Guard g, Expr sub) {
  booleanGuardFor(g, sub) and
  exists(Expr op |
    op = getALogicalOperand(g) and
    sub.getParent*() = op and
    isWeakCheck(op, sub)
  )
}

/**
 * A conditional involving the path that is not considered to be a weak check.
 */
class StrongPathCheck extends DataFlow::ExprNode {
  StrongPathCheck() {
    exists(Guard g, Expr sub, GuardValue v |
      g = this.(GuardedDataFlowNode).getAGuard(sub, v) and
      exists(v.asBooleanValue()) and
      not isWeakGuardFor(g, sub)
    )
  }
}

/** A data flow sink for uncontrolled data in path expressions. */
class Sink extends DataFlow::Node {
  Sink() {
    this instanceof TP::Sink
    or
    sinkNode(this, "path-injection")
  }
}

/** A sanitizer for uncontrolled data in path expressions. */
class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    this instanceof TP::Sanitizer and not this instanceof TP::PathCheck
    or
    this instanceof TP::RequestMapPathSanitizer
    or
    // Characters are not sanitized, as a path can be rebuilt character by character.
    this instanceof SimpleTypeSanitizedExpr and
    not this.getType() instanceof CharType
    or
    this instanceof GuidSanitizedExpr
    or
    this instanceof StrongPathCheck
  }
}

private module TaintedPathExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof TP::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** A taint-tracking module for uncontrolled data in path expressions. */
module TaintedPathExtended = TaintTracking::Global<TaintedPathExtendedConfig>;
