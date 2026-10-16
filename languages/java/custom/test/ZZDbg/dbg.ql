import java
import semmle.code.java.security.AndroidIntentRedirectionQuery
import semmle.code.java.dataflow.FlowSources

from DataFlow::Node n, string kind
where
  (n instanceof ActiveThreatModelSource and kind = "source")
  or (n instanceof IntentRedirectionSink and kind = "sink")
  or (n instanceof IntentRedirectionSanitizer and kind = "sanitizer")
select n, kind, n.getLocation().getFile().getBaseName(), n.getLocation().getStartLine()
