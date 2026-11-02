/**
 * @name Use of a weak cryptographic algorithm with the Windows CryptoAPI
 * @description Selecting a broken or risky cipher (such as DES, 3DES, RC2 or RC4)
 *              or a broken hash algorithm (such as MD5 or SHA-1) when creating a
 *              CryptoAPI key or hash allows an attacker to compromise security.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/wincrypt-weak-algorithm
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 */

import cpp
import WeakCryptoRandomness.WeakCryptoRandomness

from FunctionCall call, CryptoAlgorithmConstant constant, string description
where
  selectsCryptoAlgorithm(call, constant) and
  (
    constant.getKind() = "weak-cipher" and
    description = "broken or risky cipher " + constant.getAlgorithm()
    or
    constant.getKind() = "weak-hash" and
    description = "broken hash algorithm " + constant.getAlgorithm()
  )
select call,
  "Call to " + call.getTarget().getName() + " uses the " + description + " (selected by $@).",
  constant, constant.getConstantName()
