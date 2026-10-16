/**
 * @name Sensitive field exposed by a Django REST framework serializer
 * @description A Django REST framework model serializer that includes sensitive fields,
 *              such as password hashes, password-reset tokens, social security numbers or
 *              dates of birth, in its readable fields exposes them through the API.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/drf-serializer-sensitive-field-exposure
 * @tags security
 *       external/cwe/cwe-359
 *       external/cwe/cwe-200
 */

import python
import semmle.python.ApiGraphs
private import codeql.concepts.internal.SensitiveDataHeuristics

/** Holds if the field name `name` indicates sensitive data that should not be readable. */
bindingset[name]
predicate isSensitiveFieldName(string name) {
  (
    HeuristicNames::nameIndicatesSensitiveData(name,
      [
        SensitiveDataClassification::password(), SensitiveDataClassification::secret(),
        SensitiveDataClassification::private()
      ])
    or
    name.regexpMatch("(?i).*(reset.?token|(access|refresh|auth|api|session).?token|(otp|mfa|totp).?(secret|seed)).*")
    or
    name.regexpMatch("(?i)(.*_)?dob(_.*)?")
  ) and
  not name.regexpMatch("(?i).*(expir|created|updated|_at$|_count$|_set$|^is_|^has_).*")
}

/** A Django REST framework model serializer class. */
class ModelSerializerClass extends Class {
  ModelSerializerClass() {
    this.getParent() =
      API::moduleImport("rest_framework")
          .getMember("serializers")
          .getMember(["ModelSerializer", "HyperlinkedModelSerializer"])
          .getASubclass*()
          .asSource()
          .asExpr()
  }

  /** Gets the inner `Meta` class of this serializer. */
  Class getMeta() { result.getScope() = this and result.getName() = "Meta" }

  /** Gets the value assigned to `name` in the `Meta` class of this serializer. */
  Expr getMetaValue(string name) {
    exists(AssignStmt a |
      a.getScope() = this.getMeta() and
      a.getATarget().(Name).getId() = name and
      result = a.getValue()
    )
  }

  /** Holds if `field` is declared write-only on this serializer. */
  predicate isWriteOnly(string field) {
    // Meta.extra_kwargs = {"password": {"write_only": True}}
    exists(KeyValuePair outer, KeyValuePair inner |
      outer = this.getMetaValue("extra_kwargs").(Dict).getAnItem() and
      outer.getKey().(StringLiteral).getText() = field and
      inner = outer.getValue().(Dict).getAnItem() and
      inner.getKey().(StringLiteral).getText() = "write_only" and
      inner.getValue().(True).booleanValue() = true
    )
    or
    // Meta.write_only_fields = ("password",)
    field = this.getMetaValue("write_only_fields").getASubExpression().(StringLiteral).getText()
    or
    // password = serializers.CharField(write_only=True)
    exists(AssignStmt a, Keyword kw |
      a.getScope() = this and
      a.getATarget().(Name).getId() = field and
      kw = a.getValue().(Call).getAKeyword() and
      kw.getArg() = "write_only" and
      kw.getValue().(True).booleanValue() = true
    )
  }

  /** Holds if `field` is excluded via `Meta.exclude`. */
  predicate isExcluded(string field) {
    field = this.getMetaValue("exclude").getASubExpression().(StringLiteral).getText()
  }

  /** Gets the model class named by `Meta.model`, if it is defined in the analyzed code. */
  Class getModel() { result.getName() = this.getMetaValue("model").(Name).getId() }
}

/** Gets the name of a model field (`x = models.SomeField(...)`) declared on `model`. */
string modelField(Class model) {
  exists(AssignStmt a |
    a.getScope() = model and
    a.getValue().(Call).getFunc().(Attribute).getName().matches("%Field") and
    result = a.getATarget().(Name).getId()
  )
}

/** Gets a sensitive readable field of `ser`, with `fields` the `Meta.fields` value. */
string exposedSensitiveField(ModelSerializerClass ser, Expr fields) {
  fields = ser.getMetaValue("fields") and
  (
    result = fields.(List).getAnElt().(StringLiteral).getText()
    or
    result = fields.(Tuple).getAnElt().(StringLiteral).getText()
    or
    fields.(StringLiteral).getText() = "__all__" and result = modelField(ser.getModel())
  ) and
  isSensitiveFieldName(result) and
  not ser.isWriteOnly(result) and
  not ser.isExcluded(result)
}

from ModelSerializerClass ser, Expr fields, string names
where
  names =
    strictconcat(string f | f = exposedSensitiveField(ser, fields) | "'" + f + "'", ", " order by f)
select fields,
  "Serializer " + ser.getName() + " exposes sensitive field(s) " + names + " through the API."
