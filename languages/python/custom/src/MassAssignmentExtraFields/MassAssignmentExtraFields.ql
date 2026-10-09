/**
 * @name Mass assignment from a request model that allows extra fields
 * @description Copying every field of a Pydantic model that accepts arbitrary extra
 *              fields onto another object with `setattr` lets a client set any
 *              attribute, including privileged ones such as `role`.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id py/mass-assignment-extra-fields
 * @tags security
 *       external/cwe/cwe-915
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

/** Holds if `e` selects the Pydantic "allow" behavior for extra fields. */
predicate isAllowValue(Expr e) {
  e.(StringLiteral).getText() = "allow"
  or
  e =
    API::moduleImport("pydantic")
        .getMember("Extra")
        .getMember("allow")
        .getAValueReachableFromSource()
        .asExpr()
  or
  e =
    API::moduleImport("pydantic")
        .getMember("config")
        .getMember("Extra")
        .getMember("allow")
        .getAValueReachableFromSource()
        .asExpr()
}

/**
 * Holds if the class defined by `cls` explicitly configures its handling of extra
 * fields with `value`.
 */
predicate extraSetting(ClassExpr cls, Expr value) {
  // class Model(BaseModel, extra=Extra.allow)
  exists(Keyword kw | kw = cls.getAKeyword() and kw.getArg() = "extra" and value = kw.getValue())
  or
  exists(AssignStmt a, Expr config |
    a = cls.getInnerScope().getAStmt() and
    a.getATarget().(Name).getId() = "model_config" and
    config = a.getValue()
  |
    // model_config = ConfigDict(extra="allow")
    exists(Keyword kw |
      kw = config.(Call).getANamedArg() and kw.getArg() = "extra" and value = kw.getValue()
    )
    or
    // model_config = {"extra": "allow"}
    exists(KeyValuePair kv |
      kv = config.(Dict).getAnItem() and
      kv.getKey().(StringLiteral).getText() = "extra" and
      value = kv.getValue()
    )
  )
  or
  // class Config: extra = "allow"
  exists(ClassDef configDef, AssignStmt a |
    configDef = cls.getInnerScope().getAStmt() and
    configDef.getDefinedClass().getName() = "Config" and
    a = configDef.getDefinedClass().getAStmt() and
    a.getATarget().(Name).getId() = "extra" and
    value = a.getValue()
  )
}

/** Gets a reference to a Pydantic model class that accepts arbitrary extra fields. */
API::Node extraAllowModel() {
  result = API::moduleImport("pydantic").getMember("BaseModel").getASubclass+() and
  exists(Expr value |
    extraSetting(result.asSource().asExpr(), value) and
    isAllowValue(value)
  )
  or
  // Subclasses inherit the setting unless they override it.
  result = extraAllowModel().getASubclass() and
  not extraSetting(result.asSource().asExpr(), _)
}

/** Gets an instance of the extra-fields-accepting model class `model`. */
API::Node extraAllowInstance(API::Node model) {
  model = extraAllowModel() and
  (
    result = model.getReturn()
    or
    result = model.getInstanceFromAnnotation()
    or
    result =
      model
          .getMember([
              "model_validate", "model_validate_json", "model_validate_strings", "parse_obj",
              "parse_raw", "parse_file"
            ])
          .getReturn()
  )
}

/**
 * Gets a call that returns all fields (including extra fields) of an instance of
 * the model class `model`, such as `body.model_dump()`.
 */
DataFlow::Node dumpAllFields(API::Node model) {
  exists(DataFlow::Node obj | obj = extraAllowInstance(model).getAValueReachableFromSource() |
    exists(DataFlow::MethodCallNode call | result = call |
      call.calls(obj, ["model_dump", "dict"]) and
      // An explicit `include` restricts the fields to an allowlist.
      not exists(call.getArgByName("include"))
    )
    or
    exists(DataFlow::CallCfgNode call | result = call |
      call = API::builtin("vars").getACall() and
      call.getArg(0) = obj
    )
  )
}

/**
 * Holds if the loop `loop` compares the loop key variable `key` against a
 * collection, for example `if key in ALLOWED_FIELDS`, which acts as an allowlist.
 */
predicate hasKeyMembershipCheck(For loop, Variable key) {
  exists(Compare cmp, Cmpop op |
    loop.contains(cmp) and
    cmp.getLeft().(Name).getVariable() = key and
    cmp.getOp(0) = op and
    (op instanceof In or op instanceof NotIn)
  )
}

from For loop, DataFlow::Node dump, API::Node model, Variable key, DataFlow::CallCfgNode setattrCall
where
  dump = dumpAllFields(model) and
  // for key, value in dump.items():
  exists(DataFlow::MethodCallNode items |
    items.calls(any(DataFlow::Node recv | dump.(DataFlow::LocalSourceNode).flowsTo(recv)), "items") and
    loop.getIter() = items.asExpr()
  ) and
  loop.getTarget().(Tuple).getElt(0).(Name).getVariable() = key and
  //   setattr(target, key, value)
  setattrCall = API::builtin("setattr").getACall() and
  loop.contains(setattrCall.asExpr()) and
  setattrCall.getArg(1).asExpr().(Name).getVariable() = key and
  not hasKeyMembershipCheck(loop, key)
select setattrCall,
  "Every field of $@, which accepts arbitrary extra fields, is assigned to an object, allowing a client to set unintended attributes.",
  model.asSource(), model.asSource().asExpr().(ClassExpr).getName()
