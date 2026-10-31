/**
 * @name Hard-coded encryption key (extended)
 * @description Using hard-coded keys for encryption is not secure, because potential attackers can easily guess them.
 *              This variant also covers the CommonCrypto API (`CCCrypt`, `CCCryptorCreate`) and keys stored in
 *              global constants or property initializers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id swift/custom/hardcoded-key
 * @tags security
 *       external/cwe/cwe-321
 */

import swift
import CredentialAndDataExposure.HardcodedEncryptionKey
import ExtendedHardcodedKeyFlow::PathGraph

from ExtendedHardcodedKeyFlow::PathNode source, ExtendedHardcodedKeyFlow::PathNode sink, Expr origin
where
  ExtendedHardcodedKeyFlow::flowPath(source, sink) and
  isHardcodedKeySource(source.getNode(), origin)
select sink.getNode(), source, sink,
  "The key '" + sink.getNode().toString() + "' has been initialized with hard-coded values from $@.",
  origin, origin.toString()
