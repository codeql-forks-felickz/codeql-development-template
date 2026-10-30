/**
 * @name Encryption key received over cleartext HTTP
 * @description Using data received over an unencrypted `http://` connection as an encryption key
 *              lets a network attacker read or replace the key.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/custom/encryption-key-from-cleartext-http
 * @tags security
 *       external/cwe/cwe-319
 *       external/cwe/cwe-322
 */

import swift
import CredentialAndDataExposure.EncryptionKeyFromCleartextHttp
import EncryptionKeyFromCleartextHttpFlow::PathGraph

from
  EncryptionKeyFromCleartextHttpFlow::PathNode source,
  EncryptionKeyFromCleartextHttpFlow::PathNode sink
where EncryptionKeyFromCleartextHttpFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This encryption key is derived from $@, which is received over a cleartext HTTP connection.",
  source, "response data"
