/**
 * @name Use of a non-cryptographic pseudo-random number generator
 * @description Statistical pseudo-random number generators such as `rand()` produce
 *              predictable output and must not be used where unpredictability is
 *              required for security.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.8
 * @precision low
 * @id cpp/custom/weak-prng
 * @tags security
 *       external/cwe/cwe-338
 */

import cpp
import WeakCryptoRandomness.WeakCryptoRandomness

from WeakPrngCall call
where not call instanceof ExprInVoidContext
select call,
  "Call to " + call.getTarget().getName() +
    ", a non-cryptographic pseudo-random number generator whose output is predictable."
