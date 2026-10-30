/**
 * @name Insecure handling of security-sensitive resources
 * @description Untrusted data used to change system configuration or to load a
 *              library, reverse DNS results used in security decisions,
 *              unquoted process command lines and passwords written to
 *              standard error can let an attacker control security-sensitive
 *              resources or expose credentials.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id cpp/file-upload-resource-handling
 * @tags security
 *       external/cwe/cwe-015
 *       external/cwe/cwe-114
 *       external/cwe/cwe-247
 *       external/cwe/cwe-350
 *       external/cwe/cwe-428
 *       external/cwe/cwe-535
 */

import cpp
import FileUploadResourceHandling

from Expr alert, string message, Element related, string relatedLabel
where
  exists(FlowSource source |
    externalConfigControl(alert, source) and
    message =
      "This system configuration setting is changed by " +
        alert.(FunctionCall).getTarget().getName() + " using untrusted data from $@." and
    related = [source.asExpr(), source.asIndirectExpr(), source.asDefiningArgument()] and
    relatedLabel = source.getSourceType()
    or
    untrustedLibraryLoad(alert, source) and
    message =
      "The library loaded by " + alert.(FunctionCall).getTarget().getName() +
        " is chosen by untrusted data from $@." and
    related = [source.asExpr(), source.asIndirectExpr(), source.asDefiningArgument()] and
    relatedLabel = source.getSourceType()
  )
  or
  exists(ReverseDnsLookupCall lookup |
    dnsSecurityDecision(alert, lookup) and
    message = "This security decision relies on the host name returned by $@." and
    related = lookup and
    relatedLabel = "a reverse DNS lookup"
  )
  or
  exists(LocalVariable buffer, string cmdLine |
    unquotedCommandLineBuffer(alert, buffer, cmdLine) and
    message =
      alert.(FunctionCall).getTarget().getName() +
        " is called with a NULL application name and the unquoted command line in $@, which contains spaces in the executable path." and
    related = buffer and
    relatedLabel = buffer.getName()
  )
  or
  exists(Element sensitive |
    sensitiveDataToStderr(alert, sensitive) and
    message = "This writes $@ to standard error." and
    related = sensitive and
    relatedLabel = "sensitive data (" + sensitive.toString() + ")"
  )
select alert, message, related, relatedLabel
