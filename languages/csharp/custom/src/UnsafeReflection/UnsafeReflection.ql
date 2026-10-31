/**
 * @name Use of externally-controlled input to select classes or code
 * @description Resolving or instantiating a type whose name is controlled by a user
 *              allows the user to load and construct arbitrary types, running their
 *              constructors and other code that the application did not intend to run.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id cs/unsafe-reflection
 * @tags security
 *       external/cwe/cwe-470
 */

import csharp
import semmle.code.csharp.commons.ComparisonTest
import semmle.code.csharp.controlflow.Guards
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import UnsafeReflectionFlow::PathGraph

/**
 * A string argument that names a type (or the assembly containing it) that is
 * resolved or instantiated through reflection.
 */
class ReflectionTypeNameSink extends DataFlow::ExprNode {
  ReflectionTypeNameSink() {
    exists(Call c, Callable target, Parameter p |
      target = c.getTarget() and
      p = target.getAParameter() and
      p.getType() instanceof StringType and
      this.getExpr() = c.getArgumentForParameter(p)
    |
      // System.Type.GetType(string typeName, ...) and Type.GetTypeFromProgID(string progID, ...)
      target.getDeclaringType().hasFullyQualifiedName("System", "Type") and
      target.hasName(["GetType", "GetTypeFromProgID"]) and
      p.getPosition() = 0
      or
      // System.Reflection.Assembly / Module .GetType(string name, ...) and Assembly.CreateInstance(string typeName, ...)
      target
          .getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName("System.Reflection", ["Assembly", "Module"]) and
      target.hasName(["GetType", "CreateInstance"]) and
      p.getPosition() = 0
      or
      // System.Activator.CreateInstance(From)(string assemblyName, string typeName, ...)
      target.getDeclaringType().hasFullyQualifiedName("System", "Activator") and
      target.hasName(["CreateInstance", "CreateInstanceFrom"]) and
      p.hasName(["assemblyName", "assemblyFile", "typeName"])
      or
      // System.AppDomain.CreateInstance*(string assemblyName, string typeName, ...)
      target.getDeclaringType().hasFullyQualifiedName("System", "AppDomain") and
      target.getName().matches("CreateInstance%") and
      p.hasName(["assemblyName", "assemblyFile", "typeName"])
    )
  }
}

/**
 * Holds if `guard` restricts `e` to an allow-listed value when it evaluates to `branch`,
 * either by membership in a collection (`allowed.Contains(e)`) or by equality with a
 * compile-time constant.
 */
private predicate allowListGuard(Guard guard, Expr e, GuardValue branch) {
  exists(MethodCall mc | mc = guard |
    mc.getTarget().hasName(["Contains", "ContainsKey"]) and
    mc.getAnArgument() = e and
    branch.asBooleanValue() = true
  )
  or
  exists(ComparisonTest ct | ct.getExpr() = guard |
    ct.getAnArgument() = e and
    ct.getAnArgument() instanceof StringLiteral and
    (
      ct.getComparisonKind().isEquality() and branch.asBooleanValue() = true
      or
      ct.getComparisonKind().isInequality() and branch.asBooleanValue() = false
    )
  )
}

module UnsafeReflectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ReflectionTypeNameSink }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::BarrierGuard<allowListGuard/3>::getABarrierNode()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UnsafeReflectionFlow = TaintTracking::Global<UnsafeReflectionConfig>;

from UnsafeReflectionFlow::PathNode source, UnsafeReflectionFlow::PathNode sink
where UnsafeReflectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This type name, which is used to load or instantiate a type through reflection, depends on a $@.",
  source.getNode(), "user-provided value"
