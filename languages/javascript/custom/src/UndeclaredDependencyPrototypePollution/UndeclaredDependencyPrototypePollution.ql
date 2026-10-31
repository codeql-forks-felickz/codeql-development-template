/**
 * @name Prototype-polluting merge call with undeclared dependency
 * @description Recursively merging a user-controlled object with a library that is not
 *              declared in any `package.json` may use a version that allows an attacker
 *              to modify the built-in Object prototype.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision medium
 * @id js/undeclared-dependency-prototype-pollution
 * @tags security
 *       external/cwe/cwe-1321
 *       external/cwe/cwe-915
 */

import javascript
import semmle.javascript.security.dataflow.PrototypePollutionQuery
import DataFlow::DeduplicatePathGraph<PrototypePollutionFlow::PathNode, PrototypePollutionFlow::PathGraph>

/**
 * Holds if some versions of the NPM package `id` have a prototype-polluting deep merge.
 * This is the same list of packages that the stock `js/prototype-pollution` query
 * checks against the declared version.
 */
bindingset[id]
predicate hasVulnerableVersions(string id) {
  id =
    [
      "assign-deep", "deep-extend", "defaults-deep", "extend", "just-extend", "jquery", "merge",
      "merge-deep", "merge-options", "node.extend"
    ]
  or
  id.matches("lodash%")
}

/**
 * A source operand of a deep merge call imported from a package that has vulnerable
 * versions, where no `package.json` declares the package, so its version is unknown.
 * When the package is declared, the stock `js/prototype-pollution` query decides
 * based on the declared version instead.
 */
class UndeclaredDeepExtendSink extends Sink {
  ExtendCall call;
  string moduleName;

  UndeclaredDeepExtendSink() {
    this = call.getASourceOperand() and
    call.isDeep() and
    exists(DataFlow::ModuleImportNode imp |
      call = [imp.getACall(), imp.getAMemberCall(_)] and
      moduleName = imp.getPath().(FilePath).getPackagePrefix() and
      hasVulnerableVersions(moduleName) and
      not imp = DataFlow::dependencyModuleImport(_)
    )
  }

  override predicate dependencyInfo(string moduleName_, Locatable loc) {
    moduleName_ = moduleName and
    loc = call.asExpr()
  }
}

from PathNode source, PathNode sink, string moduleName, Locatable callLoc
where
  PrototypePollutionFlow::flowPath(source.getAnOriginalPathNode(), sink.getAnOriginalPathNode()) and
  sink.getNode().(UndeclaredDeepExtendSink).dependencyInfo(moduleName, callLoc)
select sink.getNode(), source, sink,
  "Prototype pollution may be caused by merging a $@ using $@, whose version is not declared in any package.json.",
  source, "user-controlled value", callLoc, moduleName
