/**
 * @name Directory listing enabled on default servlet
 * @description Enabling directory listings on the servlet container's default servlet
 *              lets unauthenticated users enumerate and download files from any
 *              web-accessible directory that has no welcome file.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision high
 * @id java/servlet-directory-listing-enabled
 * @tags security
 *       external/cwe/cwe-548
 */

import java
import semmle.code.xml.WebXML

/**
 * Holds if `servletClass` is a default (static resource) servlet and `paramName`
 * is the init parameter that controls whether it renders directory listings.
 */
bindingset[servletClass]
predicate directoryListingParam(string servletClass, string paramName) {
  // Tomcat and Tomcat-derived containers (for example GlassFish, TomEE).
  servletClass = "org.apache.catalina.servlets.DefaultServlet" and paramName = "listings"
  or
  // Jetty 9 to 12.
  servletClass =
    [
      "org.eclipse.jetty.servlet.DefaultServlet",
      "org.eclipse.jetty.ee8.servlet.DefaultServlet",
      "org.eclipse.jetty.ee9.servlet.DefaultServlet",
      "org.eclipse.jetty.ee10.servlet.DefaultServlet",
      "org.eclipse.jetty.ee11.servlet.DefaultServlet"
    ] and
  paramName = "dirAllowed"
}

from
  WebServlet servlet, XmlElement initParam, XmlElement paramValue, string servletClass,
  string paramName
where
  servletClass = servlet.getAChild("servlet-class").getTextValue().trim() and
  directoryListingParam(servletClass, paramName) and
  initParam = servlet.getAChild("init-param") and
  initParam.getAChild("param-name").getTextValue().trim() = paramName and
  paramValue = initParam.getAChild("param-value") and
  paramValue.getTextValue().trim().toLowerCase() = "true"
select paramValue,
  "Directory listing is enabled on the default servlet '" + servletClass +
    "', exposing the names and contents of web-accessible files."
