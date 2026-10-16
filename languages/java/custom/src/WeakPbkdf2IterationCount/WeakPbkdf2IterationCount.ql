/**
 * @name Password-based key derivation with too few iterations
 * @description Deriving a cryptographic key from a password with PBKDF2 (or another
 *              password-based scheme) using a very low iteration count makes
 *              brute-force and dictionary attacks against the password cheap.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/weak-pbkdf2-iteration-count
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-916
 */

import java
import semmle.code.java.dataflow.DataFlow

/** The minimum acceptable iteration count (NIST SP 800-132 lower bound). */
int minIterations() { result = 1000 }

/**
 * Holds if `arg` is the iteration-count argument of a `PBEKeySpec` or
 * `PBEParameterSpec` constructor call `spec`.
 */
predicate iterationCountArg(ClassInstanceExpr spec, Expr arg) {
  exists(RefType t | t = spec.getConstructedType() |
    t.hasQualifiedName("javax.crypto.spec", "PBEKeySpec") and
    spec.getNumArgument() >= 3 and
    arg = spec.getArgument(2)
    or
    t.hasQualifiedName("javax.crypto.spec", "PBEParameterSpec") and
    arg = spec.getArgument(1)
  )
}

module LowIterationCountConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(CompileTimeConstantExpr).getIntValue() < minIterations()
  }

  predicate isSink(DataFlow::Node sink) { iterationCountArg(_, sink.asExpr()) }
}

module LowIterationCountFlow = DataFlow::Global<LowIterationCountConfig>;

from ClassInstanceExpr spec, DataFlow::Node source, DataFlow::Node sink, int iterations
where
  LowIterationCountFlow::flow(source, sink) and
  iterationCountArg(spec, sink.asExpr()) and
  iterations = source.asExpr().(CompileTimeConstantExpr).getIntValue()
select spec,
  "Password-based key derivation uses only " + iterations + " iteration(s); use at least " +
    minIterations() + " (current guidance for PBKDF2-HMAC-SHA256 is 600000)."
