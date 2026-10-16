/**
 * Provides a taint-tracking configuration for reasoning about cross-site
 * scripting (XSS) through ASP.NET Core `ContentResult` responses that are
 * served with an HTML content type.
 */

import csharp
private import semmle.code.csharp.security.dataflow.XSSQuery as Xss
private import semmle.code.csharp.security.dataflow.flowsources.FlowSources

/** The class `Microsoft.AspNetCore.Mvc.ContentResult`. */
class ContentResultClass extends Class {
  ContentResultClass() { this.hasFullyQualifiedName("Microsoft.AspNetCore.Mvc", "ContentResult") }
}

/**
 * Holds if `e` is a constant content type that browsers render as HTML
 * (for example `text/html` or `application/xhtml+xml`).
 */
bindingset[e]
predicate isHtmlContentType(Expr e) { e.getValue().toLowerCase().matches("%html%") }

/** An assignment to the property `name` of a `ContentResult`. */
private class ContentResultPropertyAssignment extends AssignExpr {
  string name;

  ContentResultPropertyAssignment() {
    exists(PropertyAccess pa | pa = this.getLValue() |
      pa.getTarget().hasName(name) and
      pa.getTarget().getDeclaringType().getABaseType*() instanceof ContentResultClass
    )
  }

  /** Gets the name of the assigned property. */
  string getPropertyName() { result = name }

  /**
   * Gets an expression identifying the `ContentResult` object this assignment
   * writes to: the enclosing object initializer, or the qualifier variable.
   */
  Element getTargetObject() {
    result = this.getParent().(ObjectInitializer)
    or
    not this.getParent() instanceof ObjectInitializer and
    result = this.getLValue().(PropertyAccess).getQualifier().(VariableAccess).getTarget()
  }
}

/** A data flow sink for `ContentResult` XSS vulnerabilities. */
abstract class ContentResultXssSink extends DataFlow::ExprNode { }

/**
 * The value assigned to `ContentResult.Content` where the same object has
 * `ContentType` set to an HTML content type.
 */
private class ContentPropertySink extends ContentResultXssSink {
  ContentPropertySink() {
    exists(ContentResultPropertyAssignment content, ContentResultPropertyAssignment contentType |
      content.getPropertyName() = "Content" and
      contentType.getPropertyName() = "ContentType" and
      content.getTargetObject() = contentType.getTargetObject() and
      isHtmlContentType(contentType.getRValue()) and
      this.getExpr() = content.getRValue()
    )
  }
}

/**
 * The `content` argument of a `ControllerBase.Content(content, contentType, ...)`
 * call where `contentType` is an HTML content type.
 */
private class ControllerContentSink extends ContentResultXssSink {
  ControllerContentSink() {
    exists(MethodCall mc, Method m |
      mc.getTarget() = m and
      m.hasName("Content") and
      m.getDeclaringType()
          .getABaseType*()
          .hasFullyQualifiedName("Microsoft.AspNetCore.Mvc", "ControllerBase") and
      m.getNumberOfParameters() >= 2 and
      isHtmlContentType(mc.getArgument(1)) and
      this.getExpr() = mc.getArgument(0)
    )
  }
}

/** A taint-tracking configuration for `ContentResult` XSS vulnerabilities. */
module ContentResultXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ContentResultXssSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof Xss::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

/** Taint tracking for `ContentResult` XSS vulnerabilities. */
module ContentResultXssFlow = TaintTracking::Global<ContentResultXssConfig>;
