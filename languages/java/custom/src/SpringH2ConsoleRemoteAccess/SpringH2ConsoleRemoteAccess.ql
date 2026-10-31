/**
 * @name H2 database console exposed to remote hosts
 * @description Enabling the H2 web console together with `web-allow-others` in an
 *              active Spring Boot configuration exposes a database administration
 *              console to other hosts.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id java/spring-h2-console-remote-access
 * @tags security
 *       external/cwe/cwe-489
 *       external/cwe/cwe-306
 */

import java
import semmle.code.configfiles.ConfigFiles

/**
 * Gets the canonical form of a Spring Boot property name, applying relaxed
 * binding (case, `-` and `_` are ignored).
 */
bindingset[name]
string canonicalName(string name) {
  result = name.toLowerCase().replaceAll("-", "").replaceAll("_", "")
}

/** A Spring Boot `application.properties` or `application-<profile>.properties` file. */
class SpringBootPropertiesFile extends PropertiesFile {
  SpringBootPropertiesFile() { this.getStem().regexpMatch("application(-.+)?") }

  /** Gets the profile this file applies to, if it is profile-specific. */
  string getProfile() { result = this.getStem().regexpCapture("application-(.+)", 1) }

  /** Holds if this file is loaded by default (it is not profile-specific or its profile is active). */
  predicate isActive() {
    not exists(this.getProfile())
    or
    exists(JavaProperty active |
      active.getFile() instanceof SpringBootPropertiesFile and
      canonicalName(active.getEffectiveName()) = "spring.profiles.active" and
      this.getProfile() = active.getEffectiveValue().splitAt(",").trim()
    )
  }
}

/** A Spring Boot property in an active properties file with the given canonical name and value `true`. */
class ActiveTrueProperty extends JavaProperty {
  ActiveTrueProperty() {
    this.getFile().(SpringBootPropertiesFile).isActive() and
    this.getEffectiveValue().trim().toLowerCase() = "true"
  }

  /** Gets the canonical name of this property. */
  string getCanonicalName() { result = canonicalName(this.getEffectiveName()) }
}

from ActiveTrueProperty allowOthers
where
  allowOthers.getCanonicalName() = "spring.h2.console.settings.weballowothers" and
  exists(ActiveTrueProperty enabled | enabled.getCanonicalName() = "spring.h2.console.enabled")
select allowOthers,
  "The H2 database console is enabled and accepts connections from other hosts in an active configuration."
