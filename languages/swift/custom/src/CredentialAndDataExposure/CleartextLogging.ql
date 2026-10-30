/**
 * @name Cleartext logging of sensitive information (extended)
 * @description Logging sensitive information in plaintext can expose it to an attacker.
 *              This variant also treats user interface inputs with abbreviated or undelimited
 *              sensitive names (such as `ccNoTextField`, `cvvTextField` or `pinTextField`) as
 *              sensitive.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/custom/cleartext-logging
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-359
 *       external/cwe/cwe-532
 */

import swift
import CredentialAndDataExposure.CleartextLogging
import ExtendedCleartextLoggingFlow::PathGraph

from ExtendedCleartextLoggingFlow::PathNode source, ExtendedCleartextLoggingFlow::PathNode sink
where ExtendedCleartextLoggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This operation writes '" + sink.toString() +
    "' to a log file. It may contain unencrypted sensitive data from $@.", source,
  source.getNode().toString()
