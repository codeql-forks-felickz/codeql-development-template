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

module MimeLiteralConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { node.asExpr() instanceof StringLiteralExpr }

  predicate isSink(DataFlow::Node node) {
    exists(Expr expr |
      node.asExpr() = expr and
      TypeInference::inferType(expr).(StructType).getTypeItem().getCanonicalPath() = "mime::Mime"
    )
  }

  predicate isBarrier(DataFlow::Node barrier) { none() }
}

module MimeLiteralFlow = TaintTracking::Global<MimeLiteralConfig>;

/**
 * An element of a modifier tuple passed to `iron::Response::with`, such as `body` in
 * `Response::with((status::Ok, body))`.
 *
 * Tuples that contain a `Mime` modifier built from a string literal that is clearly
 * not HTML or XML set an explicit, safe `Content-Type` and are not considered sinks.
 */
class IronResponseModifierTupleElement extends DataFlow::Node {
  IronResponseModifierTupleElement() {
    exists(Call call, TupleExpr modifiers, Expr argument |
      call.getStaticTarget().getCanonicalPath() = "<iron::response::Response>::with" and
      argument = call.getPositionalArgument(0) and
      exists(DataFlow::ExprNode tupleNode, DataFlow::ExprNode argumentNode |
        tupleNode.asExpr() = modifiers and
        argumentNode.asExpr() = argument and
        DataFlow::localFlow(tupleNode, argumentNode)
      ) and
      this.asExpr() = modifiers.getAField() and
      not exists(
        Expr mimeModifier, StringLiteralExpr mimeLiteral, DataFlow::ExprNode literalNode,
        DataFlow::ExprNode mimeNode
      |
        mimeModifier = modifiers.getAField() and
        TypeInference::inferType(mimeModifier).(StructType).getTypeItem().getCanonicalPath() =
          "mime::Mime" and
        literalNode.asExpr() = mimeLiteral and
        mimeNode.asExpr() = mimeModifier and
        MimeLiteralFlow::flow(literalNode, mimeNode) and
        not mimeLiteral.getTextValue().regexpMatch("(?i).*(html|xml).*")
      )
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
