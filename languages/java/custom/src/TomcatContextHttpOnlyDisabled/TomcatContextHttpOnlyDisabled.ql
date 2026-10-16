/**
 * @name Tomcat context disables HttpOnly session cookies
 * @description Setting `useHttpOnly="false"` on a Tomcat `<Context>` removes the `HttpOnly` flag
 *              from the session cookie, so scripts injected through cross-site scripting can
 *              read the session identifier.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id java/tomcat-context-httponly-disabled
 * @tags security
 *       external/cwe/cwe-1004
 */

import java

/**
 * A Tomcat `<Context>` element, either the root element of a context descriptor
 * (`META-INF/context.xml`, `conf/context.xml`, `conf/Catalina/<host>/<app>.xml`) or a `<Context>`
 * nested in a `<Host>` element of `conf/server.xml`.
 */
class TomcatContextXmlElement extends XmlElement {
  TomcatContextXmlElement() {
    this.getName() = "Context" and
    (
      this.getParent() instanceof XmlFile
      or
      this.getParent().(XmlElement).getName() = "Host"
    )
  }
}

from TomcatContextXmlElement context, XmlAttribute useHttpOnly
where
  useHttpOnly = context.getAttribute("useHttpOnly") and
  // Tomcat parses the attribute with `Boolean.parseBoolean`, so any value other than `true`
  // (ignoring case) disables the flag. Property placeholders are resolved at runtime.
  not useHttpOnly.getValue().toLowerCase() = "true" and
  not useHttpOnly.getValue().matches("%${%}%")
select useHttpOnly, "Session cookies for this Tomcat context are created without the HttpOnly flag."
