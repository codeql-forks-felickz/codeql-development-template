/**
 * @name Fuzzer input read as a structure larger than the checked input size
 * @description A fuzzing harness casts the fuzzer-provided buffer to a structure
 *              pointer and reads a field that lies beyond the minimum input size
 *              guaranteed by its length check, reading past the end of the input.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cpp/custom/fuzzer-input-struct-overread
 * @tags security
 *       external/cwe/cwe-125
 */

import cpp
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.dataflow.new.DataFlow

/** A libFuzzer entry point: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`. */
class FuzzerEntryPoint extends Function {
  FuzzerEntryPoint() {
    this.hasGlobalName("LLVMFuzzerTestOneInput") and
    this.getNumberOfParameters() = 2
  }

  /** Gets the parameter holding the fuzzer-provided input buffer. */
  Parameter getDataParameter() { result = this.getParameter(0) }

  /** Gets the parameter holding the length of the fuzzer-provided input buffer. */
  Parameter getSizeParameter() { result = this.getParameter(1) }
}

/**
 * Gets the minimum number of input bytes that the guards of `f` guarantee to
 * be available in `bb`, or 0 if the input size is not checked.
 */
int guaranteedInputSize(FuzzerEntryPoint f, BasicBlock bb) {
  bb.getEnclosingFunction() = f and
  result =
    max(int k |
      k = 0
      or
      exists(GuardCondition g | g.ensuresLt(f.getSizeParameter().getAnAccess(), k, bb, false))
    )
}

from
  FuzzerEntryPoint f, Struct s, PointerFieldAccess fa, Field fld, int available, int needed,
  string checked
where
  DataFlow::localFlow(DataFlow::parameterNode(f.getDataParameter()),
    DataFlow::exprNode(fa.getQualifier())) and
  fld = fa.getTarget() and
  s = fld.getDeclaringType() and
  // The input buffer is reinterpreted as a pointer to a structure.
  not f.getDataParameter().getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType() = s and
  not fa.getParent+() instanceof SizeofOperator and
  needed = fld.getByteOffset() + fld.getType().getSize() and
  available = guaranteedInputSize(f, fa.getBasicBlock()) and
  available < needed and
  if available = 0
  then checked = "the input size is not checked"
  else checked = "the input is only checked to be at least " + available + " bytes long"
select fa,
  "Field $@ of " + s.getName() + " extends to byte " + needed + " of the fuzzer input, but " +
    checked + ".", fld, fld.getName()
