/**
 * @name Use of RSA without OAEP padding with the Windows CryptoAPI
 * @description Encrypting or decrypting with an RSA key without the `CRYPT_OAEP`
 *              flag uses PKCS #1 v1.5 padding, which is vulnerable to adaptive
 *              chosen-ciphertext (Bleichenbacher) attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/wincrypt-rsa-without-oaep
 * @tags security
 *       external/cwe/cwe-780
 */

import cpp
import WeakCryptoRandomness.WeakCryptoRandomness

from
  FunctionCall crypt, FunctionCall keyCreation, CryptoAlgorithmConstant rsa, Variable key,
  string function, int keyArg, int flagsArg, int oaepFlag
where
  rsaPaddingFlagsModel(function, keyArg, flagsArg, oaepFlag) and
  crypt.getTarget().hasGlobalName(function) and
  crypt.getArgument(keyArg) = key.getAnAccess() and
  crypt.getArgument(flagsArg).getValue().toInt().bitAnd(oaepFlag) = 0 and
  selectsCryptoAlgorithm(keyCreation, rsa) and
  rsa.getKind() = "rsa" and
  keyCreation.getAnArgument().(AddressOfExpr).getOperand() = key.getAnAccess()
select crypt, "Call to " + function + " uses an RSA key (created by $@) without OAEP padding.",
  keyCreation, keyCreation.getTarget().getName()
