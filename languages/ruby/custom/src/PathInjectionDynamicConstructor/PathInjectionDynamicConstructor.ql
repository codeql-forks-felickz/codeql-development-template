/**
 * @name Uncontrolled data used in path expression (including dynamically resolved constructors)
 * @description Accessing paths influenced by users can allow an attacker to access unexpected
 *              resources. This variant of `rb/path-injection` additionally treats the
 *              constructor arguments of a dynamically resolved class (for example
 *              `params[:type].constantize.new(path)`) as filesystem paths, because the
 *              resolved class may be `File`, `Dir`, `IO` or `Pathname`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id rb/path-injection-dynamic-constructor
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 *       external/cwe/cwe-099
 */

import ruby
import codeql.ruby.DataFlow
import codeql.ruby.security.PathInjectionQuery
import PathInjectionFlow::PathGraph

/** Classes whose constructor interprets its first argument as a filesystem path. */
bindingset[name]
private predicate isFileSystemClassName(string name) {
  name = ["File", "Dir", "IO", "Pathname", "::File", "::Dir", "::IO", "::Pathname"]
}

/**
 * A call that resolves a class from a string at runtime, such as
 * `name.constantize`, `name.safe_constantize` or `Object.const_get(name)`.
 */
private class DynamicConstantLookup extends DataFlow::CallNode {
  DataFlow::Node nameArg;

  DynamicConstantLookup() {
    this.getMethodName() = ["constantize", "safe_constantize"] and
    nameArg = this.getReceiver()
    or
    this.getMethodName() = "const_get" and
    nameArg = this.getArgument(0)
  }

  /**
   * Holds if the resolved class may be a filesystem class: either the name is not
   * a compile-time constant, or it is a constant naming a filesystem class.
   */
  predicate mayResolveToFileSystemClass() {
    not exists(nameArg.getConstantValue())
    or
    isFileSystemClassName(nameArg.getConstantValue().getStringlikeValue())
  }
}

/**
 * The first argument to `new` on a dynamically resolved class that may be a
 * filesystem class, for example `path` in `params[:type].constantize.new(path)`.
 */
private class DynamicConstructorPathSink extends PathInjection::Sink {
  DynamicConstructorPathSink() {
    exists(DataFlow::CallNode newCall, DynamicConstantLookup lookup |
      newCall.getMethodName() = "new" and
      lookup.flowsTo(newCall.getReceiver()) and
      lookup.mayResolveToFileSystemClass() and
      this = newCall.getArgument(0)
    )
  }
}

from PathInjectionFlow::PathNode source, PathInjectionFlow::PathNode sink
where PathInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "user-provided value"
