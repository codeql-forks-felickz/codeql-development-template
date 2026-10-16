/**
 * @name Use of externally-controlled input to select classes or code
 * @description Instantiating or invoking a type whose name is controlled by a remote user
 *              allows the user to run the constructors or members of unintended types.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cs/unsafe-reflection
 * @tags security
 *       external/cwe/cwe-470
 */

import csharp
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.security.Sanitizers
import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/** A sink for unsafe reflection: a type or assembly selector that is instantiated or invoked. */
abstract class UnsafeReflectionSink extends DataFlow::ExprNode { }

/** A barrier for unsafe reflection. */
abstract class UnsafeReflectionBarrier extends DataFlow::Node { }

/** Holds if `p` selects the assembly or type to instantiate. */
private predicate isTypeSelectorParameter(Parameter p) {
  p.hasName(["assemblyName", "assemblyFile", "typeName"]) and p.getType() instanceof StringType
  or
  p.getType().(Class).hasFullyQualifiedName("System", "Type")
}

/**
 * A type or assembly selector passed to an instantiation method, for example
 * `Activator.CreateInstance(assemblyName, typeName)`, `Activator.CreateInstance(type)`,
 * `AppDomain.CreateInstanceAndUnwrap(assemblyName, typeName)` or
 * `Assembly.CreateInstance(typeName)`.
 */
private class InstantiationSink extends UnsafeReflectionSink {
  InstantiationSink() {
    exists(MethodCall mc, Method m, int i |
      m = mc.getTarget() and
      (
        m.getDeclaringType().hasFullyQualifiedName("System", "Activator") and
        m.hasName(["CreateInstance", "CreateInstanceFrom"])
        or
        m.getDeclaringType().hasFullyQualifiedName("System", "AppDomain") and
        m.hasName([
            "CreateInstance", "CreateInstanceAndUnwrap", "CreateInstanceFrom",
            "CreateInstanceFromAndUnwrap"
          ])
        or
        m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Reflection", "Assembly") and
        m.hasName("CreateInstance")
      ) and
      isTypeSelectorParameter(m.getParameter(i)) and
      this.getExpr() = mc.getArgument(i)
    )
  }
}

/** The type on which `Type.InvokeMember` is called. */
private class InvokeMemberSink extends UnsafeReflectionSink {
  InvokeMemberSink() {
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System", "Type", "InvokeMember") and
      this.getExpr() = mc.getQualifier()
    )
  }
}

/**
 * Holds if `pred` is a type name and `succ` is the `Type` it resolves to, for example
 * `Type.GetType(name)`, `Assembly.GetType(name)` or `Module.GetType(name)`.
 */
private predicate typeLookupStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(MethodCall mc, Method m |
    m = mc.getTarget() and
    m.hasName("GetType") and
    m.getParameter(0).getType() instanceof StringType and
    (
      m.getDeclaringType().hasFullyQualifiedName("System", "Type") or
      m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Reflection", "Assembly") or
      m.getDeclaringType().getABaseType*().hasFullyQualifiedName("System.Reflection", "Module")
    ) and
    pred.asExpr() = mc.getArgument(0) and
    succ.asExpr() = mc
  )
}

/** Holds if `g` checks that `e` is contained in an allowlist, for example `allowed.Contains(e)`. */
private predicate allowListGuard(Guard g, Expr e, GuardValue v) {
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasName(["Contains", "ContainsKey"]) and
    not mc.getQualifier().getType() instanceof StringType and
    e = mc.getArgument(0) and
    v.asBooleanValue() = true
  )
}

/** Holds if `g` compares `e` with a constant, for example `e == "Plugins.Safe"`. */
private predicate constantComparisonGuard(Guard g, Expr e, GuardValue v) {
  exists(EqualityOperation cmp | cmp = g |
    e = cmp.getAnOperand() and
    exists(cmp.getAnOperand().(StringLiteral)) and
    not e instanceof StringLiteral and
    if cmp instanceof EQExpr then v.asBooleanValue() = true else v.asBooleanValue() = false
  )
  or
  exists(MethodCall mc | mc = g |
    mc.getTarget().hasFullyQualifiedName("System", "String", "Equals") and
    (
      e = mc.getQualifier() and mc.getArgument(0) instanceof StringLiteral
      or
      e = mc.getArgument(0) and mc.getArgument(1) instanceof StringLiteral
      or
      e = mc.getArgument(1) and mc.getArgument(0) instanceof StringLiteral
    ) and
    v.asBooleanValue() = true
  )
}

private class GuardBarrier extends UnsafeReflectionBarrier {
  GuardBarrier() {
    this = DataFlow::BarrierGuard<allowListGuard/3>::getABarrierNode() or
    this = DataFlow::BarrierGuard<constantComparisonGuard/3>::getABarrierNode()
  }
}

private class SimpleTypeBarrier extends UnsafeReflectionBarrier {
  SimpleTypeBarrier() {
    this instanceof SimpleTypeSanitizedExpr or
    this instanceof GuidSanitizedExpr
  }
}

module UnsafeReflectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeReflectionSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof UnsafeReflectionBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    typeLookupStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UnsafeReflectionFlow = TaintTracking::Global<UnsafeReflectionConfig>;

import UnsafeReflectionFlow::PathGraph

from UnsafeReflectionFlow::PathNode source, UnsafeReflectionFlow::PathNode sink
where UnsafeReflectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This type or assembly selector depends on a $@, allowing an attacker to instantiate or invoke unintended types.",
  source.getNode(), "user-provided value"
