/**
 * @name Base64 encoding used as encryption
 * @description An encryption function that only Base64-encodes its input does not protect the data, since anyone
 *              can decode it without a key.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id swift/custom/base64-as-encryption
 * @tags security
 *       external/cwe/cwe-311
 *       external/cwe/cwe-327
 */

import swift
import CredentialAndDataExposure.Base64AsEncryption

from Base64EncodeCall call, EncryptionNamedFunction f
where base64AsEncryption(call, f)
select call,
  "This Base64 encoding is the only transformation $@ applies to its input, so the data is not encrypted.",
  f, f.getName()
