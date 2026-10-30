/**
 * @name Reflected cross-site scripting in an ERB script block
 * @description Writing user input into an unquoted JavaScript context in an ERB
 *              `<script>` block allows for a cross-site scripting vulnerability,
 *              because the default HTML escaping of `<%= ... %>` does not
 *              escape JavaScript syntax such as `;`, `(` or `${`.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id rb/reflected-xss-script-context
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import codeql.ruby.AST
import codeql.ruby.ast.Erb
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking
import codeql.ruby.security.XSS

/** Holds if `tok` is a literal text token at `line`:`col` in the ERB template of `f`. */
private predicate textToken(ErbFile f, ErbToken tok, int line, int col) {
  tok = f.getTemplate().getAChildNode() and
  not tok instanceof ErbCode and
  not tok instanceof ErbComment and
  line = tok.getLocation().getStartLine() and
  col = tok.getLocation().getStartColumn()
}

bindingset[l1, c1, l2, c2]
private predicate isBefore(int l1, int c1, int l2, int c2) {
  l1 < l2
  or
  l1 = l2 and c1 < c2
}

/** Holds if `tok` opens a `<script>` element that it does not also close. */
private predicate opensScript(ErbToken tok) {
  tok.getValue().regexpMatch("(?is).*<script\\b(?:(?!</script).)*")
}

/** Holds if `tok` opens a script element that executes JavaScript. */
private predicate executableScript(ErbToken tok) {
  not tok.getValue().regexpMatch("(?is).*<script[^>]*[ \\t\\r\\n]+type.*")
  or
  tok.getValue()
      .regexpMatch("(?is).*<script[^>]*[ \\t\\r\\n]+type[^>]*(?:module|(?:text|application)/(?:javascript|ecmascript|x-javascript|x-ecmascript|jscript|livescript|javascript1\\.[0-5]))[^>]*>.*")
}

/** Holds if `tok` contains a closing `</script>` tag. */
private predicate closesScript(ErbToken tok) { tok.getValue().regexpMatch("(?is).*</script.*") }

/** Holds if `tok` is a literal fragment of script content on `line`. */
private string scriptTextFragment(ErbToken tok, int line) {
  tok.getLocation().getEndLine() = line and
  result = tok.getValue().regexpCapture("(?s)(?:.*\\n)?([^\\n]*)", 1)
}

/** Gets the literal script text on `d`'s line before the output directive. */
private string scriptTextBefore(ErbOutputDirective d) {
  exists(ErbFile f, ErbToken open, int ol, int oc, int dl, int dc |
    textToken(f, open, ol, oc) and
    opensScript(open) and
    executableScript(open) and
    d.getLocation().getFile() = f and
    dl = d.getLocation().getStartLine() and
    dc = d.getLocation().getStartColumn() and
    isBefore(ol, oc, dl, dc) and
    result =
      concat(int line, int col, ErbToken tok |
        textToken(f, tok, _, _) and
        tok.getLocation().getStartLine() <= dl and
        tok.getLocation().getEndLine() >= dl and
        isBefore(tok.getLocation().getStartLine(), tok.getLocation().getStartColumn(), dl, dc) and
        (
          tok = open
          or
          isBefore(ol, oc, tok.getLocation().getStartLine(), tok.getLocation().getStartColumn())
        ) and
        line = tok.getLocation().getStartLine() and
        col = tok.getLocation().getStartColumn()
      |
        scriptTextFragment(tok, dl), "" order by line, col
      )
  )
}

/** Holds if the output directive `d` is located inside a `<script>` element. */
private predicate inScriptElement(ErbOutputDirective d) {
  exists(ErbFile f, ErbToken open, int ol, int oc, int dl, int dc |
    textToken(f, open, ol, oc) and
    opensScript(open) and
    executableScript(open) and
    d.getLocation().getFile() = f and
    dl = d.getLocation().getStartLine() and
    dc = d.getLocation().getStartColumn() and
    isBefore(ol, oc, dl, dc) and
    not exists(ErbToken close, int cl, int cc |
      textToken(f, close, cl, cc) and
      closesScript(close) and
      isBefore(ol, oc, cl, cc) and
      isBefore(cl, cc, dl, dc)
    )
  )
}

/**
 * Holds if the output directive `d` is inside a single- or double-quoted
 * JavaScript string literal on its line. Rails HTML escaping encodes `'` and `"`,
 * so the output cannot break out of such a string.
 */
private predicate inQuotedString(ErbOutputDirective d) {
  exists(string scriptText |
    scriptText = scriptTextBefore(d) and
    not scriptText
        .regexpMatch("(?:[^\"'\\\\]|\\\\.|\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')*")
  )
}

/** Holds if the output directive `d` is inside a JavaScript template literal. */
private predicate inTemplateLiteral(ErbOutputDirective d) {
  exists(string scriptText |
    scriptText = scriptTextBefore(d) and
    not scriptText.regexpMatch("(?:[^`\\\\]|\\\\.|`(?:[^`\\\\]|\\\\.)*`)*")
  )
}

/**
 * The value of a (HTML-escaping) `<%= ... %>` directive that is written into an
 * unquoted JavaScript context inside a `<script>` element.
 */
private class ScriptContextOutputSink extends DataFlow::Node {
  ScriptContextOutputSink() {
    exists(ErbOutputDirective d |
      not d.isRaw() and
      inScriptElement(d) and
      not inQuotedString(d) and
      this.asExpr().getExpr() = d.getTerminalStmt()
    )
  }
}

private module ReflectedXssScriptContextConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReflectedXss::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof ScriptContextOutputSink }

  predicate isBarrier(DataFlow::Node node) {
    node.(DataFlow::CallNode).getMethodName() = ["to_i", "to_f", "to_r", "to_c", "Integer", "Float"]
    or
    node.(DataFlow::CallNode).getMethodName() = "to_json" and
    not exists(ErbOutputDirective d |
      node.asExpr().getExpr() = d.getTerminalStmt() and
      inTemplateLiteral(d)
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    ReflectedXss::isAdditionalXssTaintStep(node1, node2)
  }
}

module ReflectedXssScriptContextFlow = TaintTracking::Global<ReflectedXssScriptContextConfig>;

import ReflectedXssScriptContextFlow::PathGraph

from ReflectedXssScriptContextFlow::PathNode source, ReflectedXssScriptContextFlow::PathNode sink
where ReflectedXssScriptContextFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to a $@ written into a JavaScript context.",
  source.getNode(), "user-provided value"
