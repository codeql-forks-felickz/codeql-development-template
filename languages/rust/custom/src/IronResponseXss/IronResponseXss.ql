/**
 * @name Cross-site scripting through an Iron response modifier tuple
 * @description Writing user input into the body of an Iron response built from a
 *              modifier tuple (for example `Response::with((status::Ok, body))`)
 *              allows for a cross-site scripting vulnerability, because Iron does
 *              not set a `Content-Type` and browsers sniff the body as HTML.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id rust/xss-iron-response-modifier
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.XssExtensions
private import codeql.rust.internal.typeinference.Type
private import codeql.rust.internal.typeinference.TypeInference as TypeInference

/**
 * An element of a modifier tuple passed to `iron::Response::with`, such as `body` in
 * `Response::with((status::Ok, body))`.
 *
 * Tuples that also contain a `Mime` modifier set an explicit `Content-Type` and are
 * not considered.
 */
class IronResponseModifierTupleElement extends DataFlow::Node {
  IronResponseModifierTupleElement() {
    exists(Call call, TupleExpr modifiers |
      call.getStaticTarget().getCanonicalPath() = "<iron::response::Response>::with" and
      modifiers = call.getPositionalArgument(0) and
      this.asExpr() = modifiers.getAField() and
      not TypeInference::inferType(modifiers.getAField())
          .(StructType)
          .getTypeItem()
          .getCanonicalPath() = "mime::Mime"
    )
  }
}

module IronResponseXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node instanceof Xss::Source }

  predicate isSink(DataFlow::Node node) { node instanceof IronResponseModifierTupleElement }

  predicate isBarrier(DataFlow::Node barrier) { barrier instanceof Xss::Barrier }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module IronResponseXssFlow = TaintTracking::Global<IronResponseXssConfig>;

import IronResponseXssFlow::PathGraph

from IronResponseXssFlow::PathNode sourceNode, IronResponseXssFlow::PathNode sinkNode
where IronResponseXssFlow::flowPath(sourceNode, sinkNode)
select sinkNode.getNode(), sourceNode, sinkNode, "Cross-site scripting vulnerability due to a $@.",
  sourceNode.getNode(), "user-provided value"
