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

predicate keyCreationFlowsTo(FunctionCall keyCreation, FunctionCall crypt, int keyArg) {
  exists(DataFlow::Node keyDefinition |
    (
      keyCreation.getTarget().hasGlobalName("CryptGenKey") and
      keyDefinition.asDefiningArgument() = keyCreation.getArgument(3)
      or
      keyCreation.getTarget().hasGlobalName("CryptDeriveKey") and
      keyDefinition.asDefiningArgument() = keyCreation.getArgument(4)
    ) and
    DataFlow::localFlow(keyDefinition, DataFlow::exprNode(crypt.getArgument(keyArg)))
  )
}

from
  FunctionCall crypt, FunctionCall keyCreation, CryptoAlgorithmConstant rsa, string function,
  int keyArg, int flagsArg, int oaepFlag
where
  rsaPaddingFlagsModel(function, keyArg, flagsArg, oaepFlag) and
  crypt.getTarget().hasGlobalName(function) and
  keyCreationFlowsTo(keyCreation, crypt, keyArg) and
  crypt.getArgument(flagsArg).getValue().toInt().bitAnd(oaepFlag) = 0 and
  selectsCryptoAlgorithm(keyCreation, rsa) and
  rsa.getKind() = "rsa" and
  not exists(FunctionCall otherKeyCreation |
    otherKeyCreation != keyCreation and
    keyCreationFlowsTo(otherKeyCreation, crypt, keyArg)
  ) and
  not (
    function = "CryptEncrypt" and
    crypt.getArgument(4).getValue().toInt() = 0
  )
select crypt, "Call to " + function + " uses an RSA key (created by $@) without OAEP padding.",
  keyCreation, keyCreation.getTarget().getName()
