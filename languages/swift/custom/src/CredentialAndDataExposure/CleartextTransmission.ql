/**
 * @name Cleartext transmission of sensitive information (extended)
 * @description Transmitting sensitive information across a network in cleartext can expose it to an attacker.
 *              This variant also tracks sensitive values that are wrapped in request model structs, for
 *              example an Alamofire `parameters:` value built from a password.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/custom/cleartext-transmission
 * @tags security
 *       external/cwe/cwe-319
 */

import swift
import codeql.swift.security.CleartextTransmissionQuery
import CredentialAndDataExposure.CredentialAndDataExposure
import CleartextTransmissionFlow::PathGraph

from CleartextTransmissionFlow::PathNode source, CleartextTransmissionFlow::PathNode sink
where CleartextTransmissionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This operation transmits '" + sink.getNode().toString() +
    "', which may contain unencrypted sensitive data from $@.", source, source.getNode().toString()
