/**
 * @name Predictable session identifier
 * @description Session identifiers built from a sequential counter (optionally with a
 *              constant prefix) can be guessed by an attacker who observes one valid
 *              identifier, allowing session hijacking or fixation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id rb/predictable-session-id
 * @tags security
 *       external/cwe/cwe-384
 *       external/cwe/cwe-330
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.DataFlow
import codeql.ruby.TaintTracking

/** Holds if `name` looks like the name of a cookie that carries a session identifier. */
bindingset[name]
predicate isSessionCookieName(string name) {
  name.regexpMatch("(?i).*(session|sess_?id|(^|[^a-z])sid([^a-z]|$)|auth_?token|access_?token|login_?token).*")
}

/** Gets the string or symbol value of the cookie name `e`, if it is a constant. */
string cookieName(Expr e) { result = e.getConstantValue().getStringlikeValue() }

/**
 * Gets the expression holding the cookie value in the cookie argument `arg`, which is
 * either the value itself or a hash with a `value` entry.
 */
Expr cookieValue(Expr arg) {
  not arg instanceof HashLiteral and not arg instanceof Pair and result = arg
  or
  exists(Pair p |
    p = arg.(HashLiteral).getAKeyValuePair() and
    p.getKey().getConstantValue().getStringlikeValue() = "value" and
    result = p.getValue()
  )
}

/**
 * Gets the expression providing the value of a cookie whose name looks like a session
 * identifier, e.g. `value` in `response.set_cookie("SessionID", value)`,
 * `response.set_cookie("SessionID", value: value)` or `cookies[:session_id] = value`.
 */
Expr sessionCookieValue() {
  exists(MethodCall c |
    c.getMethodName() = "set_cookie" and
    isSessionCookieName(cookieName(c.getArgument(0)))
  |
    result = cookieValue(c.getArgument(1))
    or
    result = c.getKeywordArgument("value")
  )
  or
  exists(AssignExpr a, ElementReference er, MethodCall jar |
    a.getLeftOperand() = er and
    jar = er.getReceiver() and
    (
      jar.getMethodName() = "cookies"
      or
      jar.getMethodName() = "permanent" and
      jar.getReceiver().(MethodCall).getMethodName() = "cookies"
    ) and
    isSessionCookieName(cookieName(er.getArgument(0))) and
    result = cookieValue(a.getRightOperand())
  )
}

/** A variable that is used as a counter, i.e. it is incremented by a constant integer. */
class CounterVariable extends Variable {
  CounterVariable() {
    exists(AssignAddExpr inc |
      inc.getLeftOperand().(VariableAccess).getVariable() = this and
      inc.getRightOperand() instanceof IntegerLiteral
    )
  }
}

/**
 * Gets a read of a global or class variable, i.e. state that persists across requests
 * (unlike locals and instance variables of per-request objects such as controllers).
 */
VariableReadAccess persistentStateRead() {
  result.getVariable() instanceof GlobalVariable or
  result.getVariable() instanceof ClassVariable
}

/** Holds if `e` produces a value of a sequential counter. */
predicate isCounterValue(Expr e) {
  e.(AssignAddExpr).getLeftOperand().(VariableAccess).getVariable() instanceof CounterVariable
  or
  e.(VariableReadAccess).getVariable() instanceof CounterVariable
  or
  exists(AddExpr add | add = e |
    add.getAnOperand() instanceof IntegerLiteral and
    add.getAnOperand() = persistentStateRead()
  )
  or
  e.(MethodCall).getMethodName() = ["succ", "next"] and
  e.(MethodCall).getReceiver() = persistentStateRead() and
  e.(MethodCall).getNumberOfArguments() = 0
}

/** Holds if `n` is a source of cryptographically secure randomness. */
predicate isSecureRandom(DataFlow::Node n) {
  n = API::getTopLevelMember("SecureRandom").getAMethodCall(_)
  or
  n = API::getTopLevelMember("OpenSSL").getMember("Random").getAMethodCall("random_bytes")
  or
  n = API::getTopLevelMember("Random").getAMethodCall("urandom")
}

/** Holds if `input` is combined with a secure-random input at the same merge. */
predicate isSecureRandomMergeInput(DataFlow::Node input) {
  exists(
    StringLiteral literal, StringInterpolationComponent component,
    StringInterpolationComponent randomComponent, DataFlow::Node random
  |
    component = literal.getComponent(_) and
    randomComponent = literal.getComponent(_) and
    component != randomComponent and
    input.asExpr().getExpr() = component.getStmt(0) and
    random.asExpr().getExpr() = randomComponent.getStmt(0) and
    isSecureRandomNode(random)
  )
  or
  exists(AddExpr add, Expr inputOperand, Expr randomOperand, DataFlow::Node random |
    input.asExpr().getExpr() = inputOperand and
    (
      add instanceof AddExprRoot and
      inputOperand = add.(AddExprRoot).getALeaf() and
      randomOperand = add.(AddExprRoot).getALeaf()
      or
      not add instanceof AddExprRoot and
      inputOperand = add.getAnOperand() and
      randomOperand = add.getAnOperand()
    ) and
    inputOperand != randomOperand and
    random.asExpr().getExpr() = randomOperand and
    isSecureRandomNode(random)
  )
  or
  exists(LShiftExpr shift, Expr inputOperand, Expr randomOperand, DataFlow::Node random |
    input.asExpr().getExpr() = inputOperand and
    inputOperand = shift.getAnOperand() and
    randomOperand = shift.getAnOperand() and
    inputOperand != randomOperand and
    random.asExpr().getExpr() = randomOperand and
    isSecureRandomNode(random)
  )
  or
  exists(
    MethodCall join, ArrayLiteral array, Expr inputOperand, Expr randomOperand,
    DataFlow::Node random
  |
    join.getMethodName() = "join" and
    array = join.getReceiver() and
    input.asExpr().getExpr() = inputOperand and
    inputOperand = array.getAnElement() and
    randomOperand = array.getAnElement() and
    inputOperand != randomOperand and
    random.asExpr().getExpr() = randomOperand and
    isSecureRandomNode(random)
  )
}

/**
 * Gets a data-flow node whose value is returned from `m` by a `return` statement inside a
 * block (such as `mutex.synchronize do return x end`), which exits the enclosing method.
 */
DataFlow::Node blockReturnValue(Method m) {
  exists(ReturnStmt ret |
    ret.getEnclosingCallable() instanceof Block and
    ret.getEnclosingMethod() = m and
    result.asExpr().getExpr() = [ret.getValue(), ret.getValue().getDesugared()]
  )
}

/**
 * Holds if `call` is an implicit-`self` call to a method named like `m` in the same module
 * as `m`, but the call graph cannot resolve it, for example inside Sinatra route blocks that
 * are evaluated against an instance of the application class.
 */
predicate unresolvedSelfCall(MethodCall call, Method m) {
  not exists(call.getATarget()) and
  (not exists(call.getReceiver()) or call.getReceiver() instanceof SelfVariableAccess) and
  call.getMethodName() = m.getName() and
  call.getEnclosingModule() = m.getEnclosingModule()
}

/**
 * Holds if `pred` is a value returned from a method and `succ` is a call to that method,
 * covering returns from within blocks and calls the call graph does not resolve.
 */
predicate methodReturnStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Method m, MethodCall call | succ.asExpr().getExpr() = call |
    pred = blockReturnValue(m) and
    (call.getATarget() = m or unresolvedSelfCall(call, m))
    or
    pred = any(DataFlow::MethodNode mn | mn.asCallableAstNode() = m).getAReturnNode() and
    unresolvedSelfCall(call, m)
  )
}

private module SecureRandomToSessionCookieConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isSecureRandom(source) }

  predicate isSink(DataFlow::Node sink) { exists(Expr e | sink.asExpr().getExpr() = e) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    methodReturnStep(pred, succ)
  }
}

private module SecureRandomToSessionCookieFlow =
  TaintTracking::Global<SecureRandomToSessionCookieConfig>;

predicate isSecureRandomNode(DataFlow::Node node) {
  isSecureRandom(node)
  or
  exists(DataFlow::Node source |
    isSecureRandom(source) and
    SecureRandomToSessionCookieFlow::flow(source, node)
  )
}

private module CounterToSessionCookieConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isCounterValue(source.asExpr().getExpr()) }

  predicate isSink(DataFlow::Node sink) { sink.asExpr().getExpr() = sessionCookieValue() }

  predicate isBarrier(DataFlow::Node node) { isSecureRandomMergeInput(node) }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    methodReturnStep(pred, succ)
  }
}

private module CounterToSessionCookieFlow = TaintTracking::Global<CounterToSessionCookieConfig>;

import CounterToSessionCookieFlow::PathGraph

from CounterToSessionCookieFlow::PathNode source, CounterToSessionCookieFlow::PathNode sink
where
  CounterToSessionCookieFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This session identifier is derived from a $@, so other valid identifiers can be predicted.",
  source.getNode(), "sequential counter"
