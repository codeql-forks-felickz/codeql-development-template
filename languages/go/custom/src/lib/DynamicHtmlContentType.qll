/**
 * Provides a class for HTTP response bodies whose content type is set from a
 * non-constant value that may hold an HTML MIME type.
 */

import go
import semmle.go.security.Xss
import lib.FunctionFieldCallTaintStep

/**
 * Holds if `rhs` initializes string-typed field `f` in an element literal
 * whose type is elided and implied to be a pointer to a struct, as in
 * `[]*T{{F: rhs}}`. Such literals produce no field-write instruction.
 */
private predicate initializesFieldOfElidedPointerLit(DataFlow::Node rhs, Field f) {
  exists(CompositeLit lit, StructType st, int i, Expr elt |
    st = lit.getType().getUnderlyingType().(PointerType).getBaseType().getUnderlyingType() and
    elt = lit.getElement(i)
  |
    f = st.getField(elt.(KeyValueExpr).getKey().(Ident).getName()) and
    rhs.asExpr() = elt.(KeyValueExpr).getValue()
    or
    not elt instanceof KeyValueExpr and
    exists(string name | st.hasOwnField(i, name, _, _) | f = st.getField(name)) and
    rhs.asExpr() = elt
  )
}

/** Holds if `rhs` is a value written to the string-typed field `f`. */
private predicate stringFieldWrite(DataFlow::Node rhs, Field f) {
  f.getType().getUnderlyingType() instanceof StringType and
  (any(Write w).writesField(_, f, rhs) or initializesFieldOfElidedPointerLit(rhs, f))
}

/**
 * Tracks string constants that name an HTML MIME type to the content type that
 * is set for an HTTP response body.
 *
 * Field accesses are approximated field-based (a value written to field `f`
 * anywhere may be read from `f` anywhere), and calls through function-typed
 * struct fields are followed, so that a content type configured in a
 * registration table (for example `RawMime: "text/html"`) is found.
 */
private module HtmlContentTypeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // the same check as the standard library's `htmlTypeSpecified`
    source.getStringValue().regexpMatch("(?i).*html.*")
  }

  predicate isSink(DataFlow::Node sink) { sink = any(Http::ResponseBody b).getAContentTypeNode() }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(Field f | stringFieldWrite(pred, f) and succ = f.getARead())
    or
    any(FunctionFieldCallTaintStep s).step(pred, succ)
  }
}

private module HtmlContentTypeFlow = DataFlow::Global<HtmlContentTypeConfig>;

/**
 * An HTTP response body whose content type is set from a non-constant value
 * that may hold an HTML MIME type (for example `text/html`).
 *
 * The standard `SharedXss::HttpResponseBodySink` excludes every response body
 * whose content type is set from a value it cannot resolve to a constant, to
 * avoid reporting plain-text or JSON responses. This class recovers bodies for
 * which an HTML MIME type constant may reach that content type.
 */
class DynamicHtmlContentTypeResponseBody extends Http::ResponseBody {
  DynamicHtmlContentTypeResponseBody() {
    not this instanceof SharedXss::Sink and
    exists(DataFlow::Node ct | ct = this.getAContentTypeNode() |
      not exists(ct.getStringValue()) and
      HtmlContentTypeFlow::flowTo(ct)
    )
  }
}
