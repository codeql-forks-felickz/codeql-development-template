/**
 * @name Reflected cross-site scripting (extended)
 * @description Writing user input directly to an HTTP response allows for
 *              a cross-site scripting vulnerability. This variant of
 *              `go/reflected-xss` does not trust tag-name blocklist regexp
 *              replacements (such as removing `<script>` tags) as sanitizers,
 *              follows calls through function-typed struct fields, and treats
 *              a response whose content type is set from a value that may hold
 *              an HTML MIME type as HTML.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id go/custom/reflected-xss
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import go
import semmle.go.security.ReflectedXssCustomizations
import lib.XssSanitizers
import lib.DynamicHtmlContentType

module ReflectedXssExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReflectedXss::Source }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ReflectedXss::Sink
    or
    sink instanceof DynamicHtmlContentTypeResponseBody
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof ReflectedXss::Sanitizer and
    not node instanceof TagNameBlocklistReplacement
  }
}

module ReflectedXssExtendedFlow = TaintTracking::Global<ReflectedXssExtendedConfig>;

import ReflectedXssExtendedFlow::PathGraph

from
  ReflectedXssExtendedFlow::PathNode source, ReflectedXssExtendedFlow::PathNode sink, string msg,
  string part, Locatable partloc
where
  ReflectedXssExtendedFlow::flowPath(source, sink) and
  (
    exists(string kind | kind = sink.getNode().(SharedXss::Sink).getSinkKind() |
      kind = "rawtemplate" and
      msg = "Cross-site scripting vulnerability due to $@. The value is $@." and
      part = "instantiated as a raw template"
    )
    or
    not exists(sink.getNode().(SharedXss::Sink).getSinkKind()) and
    msg = "Cross-site scripting vulnerability due to $@." and
    part = ""
  ) and
  (
    partloc = sink.getNode().(SharedXss::Sink).getAssociatedLoc()
    or
    not sink.getNode() instanceof SharedXss::Sink and
    partloc = sink.getNode().getFile()
  )
select sink.getNode(), source, sink, msg, source.getNode(), "user-provided value", partloc, part
