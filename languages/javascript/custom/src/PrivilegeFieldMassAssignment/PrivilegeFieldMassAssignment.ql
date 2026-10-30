/**
 * @name Privilege field assigned from user input
 * @description Letting the client choose the value of a privilege field such as
 *              `is_admin` or `role` on a stored user record allows privilege
 *              escalation through mass assignment.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id js/privilege-field-mass-assignment
 * @tags security
 *       external/cwe/cwe-269
 *       external/cwe/cwe-915
 */

import javascript

/** Holds if `name` looks like the name of a field that grants privileges. */
bindingset[name]
predicate isPrivilegeName(string name) {
  name.regexpMatch("(?i)((is|has)_?)?(admin|administrator|super_?user|super_?admin|privileged|moderator|staff)"
      + "|((has|user)_?)?roles?|privileges?|permissions?|access_?level")
}

/** Holds if `pr` reads a privilege-named property of request data, such as `req.body.is_admin`. */
predicate isUserPrivilegeFlag(DataFlow::PropRead pr) {
  isPrivilegeName(pr.getPropertyName()) and
  pr.getBase().getALocalSource() instanceof RemoteFlowSource
}

/**
 * Holds if `e` is tested for truthiness or compared for equality in the
 * condition `cond`, for example `cond` is `e`, `!e`, `e && x` or `e === "admin"`.
 */
predicate isTestedIn(Expr e, Expr cond) {
  e = cond.getUnderlyingValue()
  or
  isTestedIn(e, cond.getUnderlyingValue().(LogicalBinaryExpr).getAnOperand())
  or
  isTestedIn(e, cond.getUnderlyingValue().(LogNotExpr).getOperand())
  or
  e = cond.getUnderlyingValue().(EqualityTest).getAnOperand()
}

/**
 * Holds if `n` is inside a branch of an `if` statement or conditional
 * expression whose condition tests `e`.
 */
predicate guardedBy(AstNode n, Expr e) {
  exists(IfStmt i |
    isTestedIn(e, i.getCondition()) and
    n.getParent*() = [i.getThen(), i.getElse()]
  )
  or
  exists(ConditionalExpr c |
    isTestedIn(e, c.getCondition()) and
    (n = c or n.getParent*() = c.getABranch())
  )
}

/** Holds if `e` is a privilege check that succeeds when `cond` is true. */
predicate isAuthorizationTest(Expr e, Expr cond) {
  e = cond.getUnderlyingValue()
  or
  exists(LogAndExpr conjunction |
    cond.getUnderlyingValue() = conjunction and
    isAuthorizationTest(e, conjunction.getAnOperand())
  )
  or
  exists(LogNotExpr neg |
    cond.getUnderlyingValue() = neg and
    isNegatedAuthorizationTest(e, neg.getOperand())
  )
  or
  exists(EqualityTest eq |
    cond.getUnderlyingValue() = eq and
    e = eq.getAnOperand() and
    eq.getPolarity() = true
  )
}

/** Holds if `e` is true when the condition `cond` is false. */
predicate isNegatedAuthorizationTest(Expr e, Expr cond) {
  exists(LogNotExpr neg |
    cond.getUnderlyingValue() = neg and
    isAuthorizationTest(e, neg.getOperand())
  )
  or
  exists(EqualityTest eq |
    cond.getUnderlyingValue() = eq and
    e = eq.getAnOperand() and
    eq.getPolarity() = false
  )
}

/** Holds if `n` is only reached after checking that the current user already holds a privilege. */
predicate guardedByAuthorizationCheck(AstNode n) {
  exists(IfStmt i, Expr e |
    (
      n.getParent*() = i.getThen() and isAuthorizationTest(e, i.getCondition())
      or
      n.getParent*() = i.getElse() and isNegatedAuthorizationTest(e, i.getCondition())
    ) and
    (
      exists(DataFlow::PropRead pr |
        pr.asExpr() = e and
        isPrivilegeName(pr.getPropertyName()) and
        not isUserPrivilegeFlag(pr)
      )
      or
      isPrivilegeName(e.(InvokeExpr).getCalleeName())
    )
  )
  or
  exists(ConditionalExpr c, Expr e |
    (
      n.getParent*() = c.getConsequent() and isAuthorizationTest(e, c.getCondition())
      or
      n.getParent*() = c.getAlternate() and isNegatedAuthorizationTest(e, c.getCondition())
    ) and
    (
      exists(DataFlow::PropRead pr |
        pr.asExpr() = e and
        isPrivilegeName(pr.getPropertyName()) and
        not isUserPrivilegeFlag(pr)
      )
      or
      isPrivilegeName(e.(InvokeExpr).getCalleeName())
    )
  )
}

/** Holds if `call` writes its arguments to a data store or constructs a model instance. */
predicate isPersistenceCall(DataFlow::InvokeNode call) {
  call.(DataFlow::MethodCallNode)
      .getMethodName()
      .regexpMatch("insert(One|Many)?|create|build|bulkCreate|upsert|save|update(One|Many)?|" +
          "findOneAndUpdate|findByIdAndUpdate|findAndModify|replaceOne|findOneAndReplace")
  or
  call instanceof DataFlow::NewNode
}

/** Holds if the object `obj` is written to a data store, possibly nested inside another object. */
predicate isPersisted(DataFlow::SourceNode obj) {
  exists(DataFlow::InvokeNode call, DataFlow::Node arg |
    isPersistenceCall(call) and
    isPersistedArgument(call, arg) and
    obj.flowsTo(arg)
  )
  or
  exists(obj.getAMethodCall(["save", "update", "upsert"]))
  or
  exists(DataFlow::SourceNode outer | isPersisted(outer) |
    obj.flowsTo(outer.getAPropertyWrite().getRhs())
  )
}

/** Holds if `arg` contains values written by the persistence call `call`. */
predicate isPersistedArgument(DataFlow::InvokeNode call, DataFlow::Node arg) {
  call instanceof DataFlow::NewNode and arg = call.getAnArgument()
  or
  exists(DataFlow::MethodCallNode method |
    method = call and
    (
      method.getMethodName() = "findAndModify" and arg = method.getArgument(2)
      or
      method.getMethodName() in [
        "updateOne", "updateMany", "findOneAndUpdate", "findByIdAndUpdate", "replaceOne",
        "findOneAndReplace"
      ] and
      arg = method.getArgument(1)
      or
      method.getMethodName() = "update" and arg = method.getArgument(0)
      or
      not method.getMethodName() in [
        "update", "updateOne", "updateMany", "findOneAndUpdate", "findByIdAndUpdate",
        "findAndModify", "replaceOne", "findOneAndReplace"
      ] and
      arg = method.getAnArgument()
    )
  )
}

/** Holds if `w` writes a privilege-named property of an object that is written to a data store. */
predicate isPersistedPrivilegeWrite(DataFlow::PropWrite w) {
  isPrivilegeName(w.getPropertyName()) and
  isPersisted(w.getBase().getALocalSource())
}

/** Gets an expression whose value may be stored by the privilege write `w`. */
Expr getAValueOrigin(DataFlow::PropWrite w) {
  isPersistedPrivilegeWrite(w) and
  (
    result = w.getRhs().asExpr()
    or
    result = w.getRhs().getALocalSource().asExpr()
    or
    exists(VarAccess access |
      w.getRhs().asExpr() = access and
      access.getVariable().isCaptured() and
      result = access.getVariable().getAnAssignedExpr()
    )
  )
}

/**
 * A check of the form `allowed.includes(x)` or `x === "customer"`, which
 * restricts `x` to known values in the guarded branch.
 */
class MembershipBarrierGuard extends DataFlow::Node {
  MembershipCandidate candidate;

  MembershipBarrierGuard() { this = candidate.getTest() }

  predicate blocksExpr(boolean outcome, Expr e) {
    candidate = e.flow() and candidate.getTestPolarity() = outcome
  }
}

/** Holds if `e` is `cond` or one of the conjuncts of `cond`. */
predicate isConjunctOf(Expr e, Expr cond) {
  e = cond.getUnderlyingValue()
  or
  isConjunctOf(e, cond.getUnderlyingValue().(LogAndExpr).getAnOperand())
}

/**
 * Holds if `n` is inside a branch of an `if` statement that is only taken
 * when the allow-list check on `checked` succeeds. Unlike barrier guards, this
 * also covers code in nested callbacks.
 */
predicate guardedByAllowList(AstNode n, Expr checked) {
  exists(IfStmt i, MembershipCandidate c |
    isConjunctOf(c.getTest().asExpr(), i.getCondition()) and
    c.getTestPolarity() = true and
    n.getParent*() = i.getThen() and
    checked = c.asExpr() and
    not exists(string member |
      c.getAMemberString() = member and
      isPrivilegeName(member)
    )
  )
}

/** Holds if `a` and `b` refer to the same access path, rooted at the same variable. */
predicate sameAccessPath(DataFlow::Node a, DataFlow::Node b) {
  exists(DataFlow::PropRead ra, DataFlow::PropRead rb |
    a = ra and
    b = rb and
    ra.getPropertyName() = rb.getPropertyName() and
    sameAccessPath(ra.getBase(), rb.getBase())
  )
  or
  exists(VarAccess va, VarAccess vb |
    a.asExpr() = va and
    b.asExpr() = vb and
    va.getVariable() = vb.getVariable()
  )
}

/** Holds if `a` and `b` read the same access path of request data, or the same variable. */
predicate sameRequestValue(Expr a, Expr b) {
  exists(DataFlow::PropRead ra, DataFlow::PropRead rb |
    ra.asExpr() = a and
    rb.asExpr() = b and
    sameAccessPath(ra, rb) and
    ra.getBase().getALocalSource() instanceof RemoteFlowSource and
    rb.getBase().getALocalSource() instanceof RemoteFlowSource
  )
  or
  a.(VarAccess).getVariable() = b.(VarAccess).getVariable()
}

module PrivilegeValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isBarrier(DataFlow::Node node) {
    node = DataFlow::MakeBarrierGuard<MembershipBarrierGuard>::getABarrierNode()
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::PropWrite w | isPersistedPrivilegeWrite(w) and sink = w.getRhs())
  }
}

module PrivilegeValueFlow = TaintTracking::Global<PrivilegeValueConfig>;

/** Holds if the value stored by `w` is chosen based on the user-controlled `flag`. */
predicate controlledByUserFlag(DataFlow::PropWrite w, DataFlow::Node flag, Expr origin) {
  isPersistedPrivilegeWrite(w) and
  origin = getAValueOrigin(w) and
  (
    PrivilegeValueFlow::flow(flag, w.getRhs()) and
    PrivilegeValueFlow::flow(flag, DataFlow::valueNode(origin))
    or
    exists(Expr e |
      guardedBy(origin, e) and
      isUserPrivilegeFlag(flag) and
      flag.(DataFlow::SourceNode).flowsToExpr(e)
    )
  )
  and
  not exists(Expr checked |
    guardedByAllowList(w.getRhs().asExpr(), checked) and
    sameRequestValue(checked, w.getRhs().asExpr())
  )
}

/** Gets a reference to a Sequelize model that declares the privilege attribute `field`. */
DataFlow::SourceNode privilegedModel(DataFlow::TypeTracker t, string field, DataFlow::Node decl) {
  t.start() and
  (
    exists(DataFlow::ClassNode cls, DataFlow::MethodCallNode init |
      init = cls.getAClassReference().getAMethodCall("init") and
      exists(init.getOptionArgument(0, field)) and
      isPrivilegeName(field) and
      result = cls and
      decl = cls
    )
    or
    exists(DataFlow::MethodCallNode define |
      define.getMethodName() = "define" and
      exists(define.getArgument(0).getStringValue()) and
      exists(define.getOptionArgument(1, field)) and
      isPrivilegeName(field) and
      result = define and
      decl = define
    )
  )
  or
  exists(DataFlow::TypeTracker t2 | result = privilegedModel(t2, field, decl).track(t2, t))
  or
  // `for (const { model } of [{ model: M }, ...])`: step from an array element to the loop variable.
  exists(ForOfStmt f, DataFlow::ArrayCreationNode arr |
    privilegedModel(t, field, decl).flowsTo(arr.getAnElement()) and
    arr.flowsToExpr(f.getIterationDomain()) and
    result = DataFlow::lvalueNode(f.getLValue())
  )
}

/** Gets a node that may refer to a model declaring the privilege attribute `field`. */
DataFlow::Node privilegedModelRef(string field, DataFlow::Node decl) {
  privilegedModel(DataFlow::TypeTracker::end(), field, decl).flowsTo(result)
}

/**
 * A call to `finale.resource` (or its predecessor `epilogue.resource`) that
 * generates REST endpoints which copy request body attributes into a model.
 */
class GeneratedRestResource extends API::CallNode {
  GeneratedRestResource() {
    this = API::moduleImport(["finale-rest", "epilogue"]).getMember("resource").getACall()
  }

  /** Holds if this resource exposes a `create` or `update` endpoint. */
  predicate allowsWrites() {
    not exists(this.getOptionArgument(0, "actions"))
    or
    this.getOptionArgument(0, "actions")
        .getALocalSource()
        .(DataFlow::ArrayCreationNode)
        .getAnElement()
        .mayHaveStringValue(["create", "update"])
  }
}

from DataFlow::Node alert, string msg, DataFlow::Node ref, string refText
where
  exists(DataFlow::PropWrite w, Expr origin |
    controlledByUserFlag(w, ref, origin) and
    not guardedByAuthorizationCheck(origin) and
    alert = w.getRhs() and
    msg = "Privilege field '" + w.getPropertyName() + "' of a stored record is set based on $@." and
    refText = "user-provided value"
  )
  or
  exists(GeneratedRestResource res, string field |
    res.allowsWrites() and
    res.getOptionArgument(0, "model") = privilegedModelRef(field, ref) and
    alert = res and
    msg = "Generated REST endpoints let clients set the privilege field '" + field + "' of $@." and
    refText = "this model"
  )
select alert, msg, ref, refText
