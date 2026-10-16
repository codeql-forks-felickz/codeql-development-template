/**
 * @name JWT payload decoded manually without signature verification
 * @description Splitting a JSON Web Token on "." and base64-decoding its claims segment,
 *              without ever looking at the signature segment, trusts claims an attacker
 *              can forge.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id py/jwt-manual-payload-decode
 * @tags security
 *       external/cwe/cwe-347
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** A call `x.split(".")`, which may be splitting a JWT into its three segments. */
class DotSplitCall extends DataFlow::MethodCallNode {
  DotSplitCall() {
    this.getMethodName() = "split" and
    this.getArg(0).asExpr().(StringLiteral).getText() = "."
  }

  /** Gets an expression that reads segment `i` of the split result. */
  Expr getSegmentRead(int i) {
    i in [0 .. 2] and
    (
      exists(Subscript sub |
        sub.getIndex().(IntegerLiteral).getValue() = i and
        this.flowsTo(DataFlow::exprNode(sub.getObject())) and
        result = sub
      )
      or
      exists(Assign assign, Tuple targets |
        assign.getValue() = this.asExpr() and
        targets = assign.getATarget() and
        result = targets.getElt(i).(Name).getVariable().getAUse().getNode()
      )
    )
  }
}

/** Gets a call to a `base64` decoding function. */
DataFlow::CallCfgNode base64Decode() {
  result =
    API::moduleImport("base64")
        .getMember(["b64decode", "urlsafe_b64decode", "standard_b64decode", "decodebytes"])
        .getACall()
}

/** Gets a call to `json.loads`. */
DataFlow::CallCfgNode jsonLoads() {
  result = API::moduleImport("json").getMember("loads").getACall()
}

from DotSplitCall split, DataFlow::CallCfgNode decode
where
  decode = base64Decode() and
  TaintTracking::localTaint(DataFlow::exprNode(split.getSegmentRead(1)), decode.getArg(0)) and
  // The decoded segment is parsed as JSON claims.
  exists(DataFlow::CallCfgNode loads | loads = jsonLoads() |
    TaintTracking::localTaint(decode, loads.getArg(0))
  ) and
  // The signature segment is never inspected.
  not exists(split.getSegmentRead(2))
select decode,
  "The claims of this token are decoded from its $@ without verifying its signature segment.",
  split, "split payload"
