/**
 * @name Forms authentication ticket protection disabled
 * @description Setting 'protection' to 'None' on the forms authentication element disables both
 *              encryption and validation of the forms authentication ticket, allowing an attacker
 *              to forge or tamper with it.
 * @kind problem
 * @id cs/forms-auth-protection-none
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @tags security
 *       external/cwe/cwe-287
 */

import csharp
import semmle.code.asp.WebConfig

from FormsElement forms, XmlAttribute protection
where
  protection = forms.getAttribute("protection") and
  protection.getValue().trim().toLowerCase() = "none"
select protection,
  "Forms authentication ticket protection is disabled ('protection=\"" + protection.getValue() +
    "\"'), so the ticket is neither encrypted nor validated."
