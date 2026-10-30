/**
 * @name Prototype-polluting TypeORM save
 * @description Saving a user-controlled object with a version of TypeORM before 0.2.25
 *              deep-merges it without skipping `__proto__` keys, which allows an attacker
 *              to modify the built-in Object prototype.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id js/typeorm-prototype-pollution
 * @tags security
 *       external/cwe/cwe-1321
 *       external/cwe/cwe-915
 */

import javascript
import semmle.javascript.dependencies.SemVer
import semmle.javascript.security.dataflow.PrototypePollutionQuery
import DataFlow::DeduplicatePathGraph<PrototypePollutionFlow::PathNode, PrototypePollutionFlow::PathGraph>

/**
 * An argument that TypeORM deep-merges with `OrmUtils.mergeDeep`, as modeled by the
 * `typeorm-deep-merge` sink kind, in a package that depends on a TypeORM version
 * before 0.2.25 (CVE-2020-8158).
 */
class TypeormDeepMergeSink extends Sink {
  ExternalNpmDependency dep;

  TypeormDeepMergeSink() {
    ModelOutput::sinkNode(this, "typeorm-deep-merge") and
    not exists(MethodCallExpr call |
      call.getMethodName() = "save" and
      call.getArgument(1) = this.asExpr() and
      isEntityObjectArgument(call.getArgument(0))
    ) and
    exists(NpmPackage pkg, DependencySemVer version |
      pkg.getAFile() = this.getLocation().getFile() and
      dep = pkg.getPackageJson().getADependenciesObject(_).getPropValue("typeorm") and
      dep.info("typeorm", version) and
      version.maybeBefore("0.2.25")
    )
  }

  override predicate dependencyInfo(string moduleName, Locatable location) {
    moduleName = "typeorm" and
    location = dep
  }
}

predicate isEntityObjectArgument(Expr entity) {
  entity.stripParens() instanceof ObjectExpr or
  entity.stripParens() instanceof NewExpr or
  exists(VarAccess access, Expr assigned |
    entity.stripParens() = access and
    assigned = access.getVariable().getAnAssignedExpr().stripParens() and
    (assigned instanceof ObjectExpr or assigned instanceof NewExpr)
  )
}

from PathNode source, PathNode sink, string moduleName, Locatable dependencyLoc
where
  PrototypePollutionFlow::flowPath(source.getAnOriginalPathNode(), sink.getAnOriginalPathNode()) and
  sink.getNode().(TypeormDeepMergeSink).dependencyInfo(moduleName, dependencyLoc)
select sink.getNode(), source, sink,
  "Prototype pollution caused by saving a $@ using a vulnerable version of $@.", source,
  "user-controlled value", dependencyLoc, moduleName
