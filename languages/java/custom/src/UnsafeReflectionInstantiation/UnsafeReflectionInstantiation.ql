/**
 * @name Reflective instantiation of a user-selected class
 * @description Using user-controlled data to choose the class that is loaded and then
 *              instantiated or invoked through reflection, without an allowlist, can let
 *              an attacker run code in unexpected classes.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id java/unsafe-reflection-instantiation
 * @tags security
 *       external/cwe/cwe-470
 */

import java
import semmle.code.java.Reflection
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

/** A call that instantiates a class or invokes a method through reflection. */
class ReflectiveUse extends MethodCall {
  ReflectiveUse() {
    this instanceof NewInstance
    or
    this.getMethod().hasQualifiedName("java.lang.reflect", "Method", "invoke")
  }
}

/**
 * A call on a `java.lang.Class` that returns a `Class`, `Constructor` or `Method`
 * belonging to (or derived from) the qualifier class.
 */
class ClassMemberLookup extends ClassMethodCall {
  ClassMemberLookup() {
    this.getMethod()
        .hasName([
            "getConstructor", "getDeclaredConstructor", "getMethod", "getDeclaredMethod",
            "asSubclass"
          ])
  }
}

/**
 * Holds if `g` is an allowlist check on `e`, such as `ALLOWED.contains(e)`,
 * `MAP.containsKey(e)`, `"x".equals(e)` or `e.matches("[A-Za-z]+")`, that holds
 * when `branch` is `true`.
 */
private predicate allowlistGuard(Guard g, Expr e, boolean branch) {
  branch = true and
  exists(MethodCall mc | mc = g |
    mc.getMethod().getDeclaringType().getASourceSupertype*() instanceof CollectionType and
    mc.getMethod().hasName("contains") and
    e = mc.getArgument(0)
    or
    mc.getMethod().getDeclaringType().getASourceSupertype*() instanceof MapType and
    mc.getMethod().hasName("containsKey") and
    e = mc.getArgument(0)
    or
    mc.getMethod().getDeclaringType() instanceof TypeString and
    mc.getMethod().hasName(["equals", "equalsIgnoreCase"]) and
    e = [mc.getQualifier(), mc.getArgument(0)]
    or
    mc.getMethod().getDeclaringType() instanceof TypeString and
    mc.getMethod().hasName("matches") and
    e = mc.getQualifier()
  )
}

module UnsafeReflectionInstantiationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(ReflectiveUse u).getQualifier() }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Class name -> `Class` returned by `Class.forName` / `ClassLoader.loadClass`
    exists(ReflectiveClassIdentifierMethodCall c |
      pred.asExpr() = c.getArgument(0) and succ.asExpr() = c
    )
    or
    // `Class` -> `Constructor` / `Method` / `Class` looked up on it
    exists(ClassMemberLookup c | pred.asExpr() = c.getQualifier() and succ.asExpr() = c)
  }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<allowlistGuard/3>::getABarrierNode()
  }
}

module UnsafeReflectionInstantiationFlow =
  TaintTracking::Global<UnsafeReflectionInstantiationConfig>;

import UnsafeReflectionInstantiationFlow::PathGraph

from
  UnsafeReflectionInstantiationFlow::PathNode source,
  UnsafeReflectionInstantiationFlow::PathNode sink, ReflectiveUse use
where
  UnsafeReflectionInstantiationFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = use.getQualifier()
select use, source, sink,
  "This reflective call uses a class selected by a $@ without an allowlist check.",
  source.getNode(), "user-provided value"
