/**
 * @name Cross-site scripting through a Spring MVC model attribute rendered by a JSP view
 * @description Adding user input to a Spring MVC model that is rendered by a JSP view
 *              without contextual output encoding allows for a cross-site scripting
 *              vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id java/xss-spring-jsp-model-attribute
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import java
import semmle.code.configfiles.ConfigFiles
import semmle.code.xml.XML
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.security.XSS

/**
 * Holds if the application configures Spring MVC to resolve view names to JSP pages.
 *
 * The standard `java/xss` query does not analyze JSP pages, and JSP scriptlet
 * expressions (`<%= ... %>`) and EL expressions (`${...}`) in template text do not
 * HTML-encode their output, so model attributes are rendered unescaped unless the
 * page explicitly encodes them.
 */
predicate usesJspViews() {
  // XML configuration, e.g.
  // `<bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">`
  exists(XmlElement e |
    e.getName().regexpMatch("(.*:)?bean") and
    e.getAttributeValue("class")
        .regexpMatch("org\\.springframework\\.web\\.servlet\\.view\\.(InternalResourceViewResolver|JstlView|InternalResourceView)")
  )
  or
  // `<property name="suffix" value=".jsp"/>` or `<property name="viewClass" value="...JstlView"/>`
  exists(XmlElement e |
    e.getName().regexpMatch("(.*:)?property") and
    (
      e.getAttributeValue("name") = "suffix" and
      e.getAttributeValue("value").trim().toLowerCase() = [".jsp", ".jspx"]
      or
      e.getAttributeValue("name") = "viewClass" and
      e.getAttributeValue("value").matches("%.JstlView")
    )
  )
  or
  // `<mvc:view-resolvers><mvc:jsp/></mvc:view-resolvers>`
  exists(XmlElement e |
    e.getName().regexpMatch("(.*:)?jsp") and
    e.getParent().(XmlElement).getName().regexpMatch("(.*:)?view-resolvers")
  )
  or
  // Java configuration, e.g. `new InternalResourceViewResolver("/WEB-INF/views/", ".jsp")`
  exists(ClassInstanceExpr cie |
    cie.getConstructedType()
        .getASourceSupertype*()
        .hasQualifiedName("org.springframework.web.servlet.view", "InternalResourceViewResolver")
  )
  or
  exists(TypeLiteral tl |
    tl.getReferencedType()
        .(RefType)
        .hasQualifiedName("org.springframework.web.servlet.view", "JstlView")
  )
  or
  // `ViewResolverRegistry.jsp(...)`
  exists(MethodCall ma |
    ma.getMethod()
        .hasQualifiedName("org.springframework.web.servlet.config.annotation",
          "ViewResolverRegistry", "jsp")
  )
  or
  // Spring Boot configuration, e.g. `spring.mvc.view.suffix=.jsp`
  exists(ConfigPair p |
    p.getEffectiveName() = ["spring.mvc.view.suffix", "spring.view.suffix"] and
    p.getEffectiveValue().trim().toLowerCase() = [".jsp", ".jspx"]
  )
}

/** A type that holds Spring MVC model attributes exposed to the rendered view. */
class SpringViewModelType extends RefType {
  SpringViewModelType() {
    this.getASourceSupertype*().hasQualifiedName("org.springframework.ui", ["Model", "ModelMap"]) and
    // Attributes added to `RedirectAttributes` become URL query parameters of the
    // redirect, rather than being rendered by a view.
    not this.getASourceSupertype*()
        .hasQualifiedName("org.springframework.web.servlet.mvc.support", "RedirectAttributes")
  }
}

/** An expression whose value is exposed to the view as a Spring MVC model attribute. */
class SpringModelAttributeValue extends Expr {
  SpringModelAttributeValue() {
    exists(MethodCall ma, Method m |
      ma.getMethod() = m and
      ma.getQualifier().getType() instanceof SpringViewModelType
    |
      m.hasName(["addAttribute", "put"]) and
      m.getNumberOfParameters() = 2 and
      this = ma.getArgument(1)
      or
      m.hasName("addAttribute") and
      m.getNumberOfParameters() = 1 and
      this = ma.getArgument(0)
    )
    or
    exists(MethodCall ma |
      ma.getMethod()
          .hasQualifiedName("org.springframework.web.servlet", "ModelAndView", "addObject")
    |
      this = ma.getArgument(ma.getNumArgument() - 1)
    )
    or
    // `new ModelAndView(viewName, modelName, modelObject)`
    exists(ClassInstanceExpr cie |
      cie.getConstructedType()
          .getASourceSupertype*()
          .hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
      cie.getNumArgument() = 3 and
      this = cie.getArgument(2)
    )
  }
}

/**
 * A model attribute value that is rendered by a JSP view, outside of a handler
 * whose return value is written directly to the response body.
 */
class SpringJspModelAttributeSink extends DataFlow::Node {
  SpringJspModelAttributeSink() {
    usesJspViews() and
    exists(SpringModelAttributeValue v | this.asExpr() = v |
      not v.getEnclosingCallable().(SpringRequestMappingMethod).isResponseBody()
    )
  }
}

module SpringJspModelXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ActiveThreatModelSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SpringJspModelAttributeSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  }
}

module SpringJspModelXssFlow = TaintTracking::Global<SpringJspModelXssConfig>;

import SpringJspModelXssFlow::PathGraph

from SpringJspModelXssFlow::PathNode source, SpringJspModelXssFlow::PathNode sink
where SpringJspModelXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to a $@ rendered by a JSP view through a Spring MVC model attribute.",
  source.getNode(), "user-provided value"
