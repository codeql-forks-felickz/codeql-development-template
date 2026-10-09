/**
 * @name Spring Boot session cookie configured without Secure or HttpOnly
 * @description Disabling the 'Secure' or 'HttpOnly' attribute of the Spring Boot session cookie
 *              exposes the session identifier to interception or to client-side scripts.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @security-severity 5.0
 * @id java/spring-boot-insecure-session-cookie-config
 * @tags security
 *       external/cwe/cwe-614
 *       external/cwe/cwe-1004
 */

import java
import semmle.code.configfiles.ConfigFiles

/** A Spring Boot `application.properties` (or profile-specific `application-*.properties`) file. */
class SpringBootApplicationPropertiesFile extends PropertiesFile {
  SpringBootApplicationPropertiesFile() {
    this.getBaseName().regexpMatch("application(-[^.]+)?\\.properties")
  }
}

/**
 * Holds if `name` is a Spring Boot session cookie property name (after relaxed binding
 * normalization) for `attribute`, which is the displayed attribute name.
 */
bindingset[name]
predicate isSessionCookieAttributeProperty(string name, string attribute) {
  exists(string normalized, string prefix, string suffix |
    normalized = name.toLowerCase().replaceAll("-", "").replaceAll("_", "") and
    prefix =
      [
        "server.servlet.session.cookie.", "server.reactive.session.cookie.",
        "server.session.cookie."
      ] and
    normalized = prefix + suffix
  |
    suffix = "secure" and attribute = "Secure"
    or
    suffix = "httponly" and attribute = "HttpOnly"
  )
}

from JavaProperty p, string attribute
where
  p.getFile() instanceof SpringBootApplicationPropertiesFile and
  isSessionCookieAttributeProperty(p.getEffectiveName(), attribute) and
  p.getEffectiveValue().trim().toLowerCase() = "false"
select p, "The Spring Boot session cookie is configured without the '" + attribute + "' attribute."
