/**
 * @name XML external entity expansion in libxmljs-compatible parsers
 * @description Parsing user input with `libxml` or `libxmljs2` and the `noent` option
 *              enabled expands external entities, which allows XXE attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id js/xxe-libxmljs-variant
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 */

import javascript
import semmle.javascript.security.dataflow.XxeQuery
import XxeFlow::PathGraph

/**
 * A call to `parseXml*` on a package that shares the `libxmljs` API but is not
 * modeled by the standard library (`codeql/javascript-all` only models `libxmljs`).
 */
class LibxmljsVariantParserInvocation extends XML::ParserInvocation {
  LibxmljsVariantParserInvocation() {
    exists(string m |
      this = API::moduleImport(["libxml", "libxmljs2"]).getMember(m).getACall().asExpr() and
      m.matches("parseXml%")
    )
  }

  override Expr getSourceArgument() { result = this.getArgument(0) }

  override predicate resolvesEntities(XML::EntityKind kind) {
    not kind = XML::InternalEntity() and
    // external entities are only resolved if the configuration option `noent` is set to `true`
    exists(Expr noent |
      this.hasOptionArgument(1, "noent", noent) and
      noent.mayHaveBooleanValue(true)
    )
  }
}

from XxeFlow::PathNode source, XxeFlow::PathNode sink
where
  XxeFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = any(LibxmljsVariantParserInvocation p).getSourceArgument()
select sink.getNode(), source, sink,
  "XML parsing depends on a $@ without guarding against external entity expansion.",
  source.getNode(), "user-provided value"
