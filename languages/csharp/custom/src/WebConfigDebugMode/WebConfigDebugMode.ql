/**
 * @name Web.config compilation debug mode enabled
 * @description Enabling compilation debug mode in Web.config can expose detailed diagnostic
 *              information and should not be used in a deployed application.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision high
 * @id cs/web/config-debug-enabled
 * @tags security
 *       external/cwe/cwe-489
 */

import csharp
import semmle.code.asp.WebConfig

from XmlElement compilation
where
  compilation.getFile() instanceof WebConfigXml and
  compilation.getName().toLowerCase() = "compilation" and
  compilation.getParent() instanceof SystemWebXmlElement and
  compilation.getAttributeValue("debug").toLowerCase() = "true"
select compilation,
  "Compilation debug mode is enabled in Web.config and should be disabled before deployment."
