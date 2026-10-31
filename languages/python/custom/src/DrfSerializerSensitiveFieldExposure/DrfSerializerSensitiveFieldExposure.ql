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
import LegacyPointsTo
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

  /** Gets a class in this serializer's inheritance hierarchy. */
  Class getAClassInHierarchy() {
    result = this
    or
    result = this.(ClassWithPointsTo).getClassObject().getASuperType().getPyClass()
  }

  /** Gets the nearest class in the serializer hierarchy that declares `field`. */
  Class getFieldDeclaration(string field) {
    result = this.getAClassInHierarchy() and
    declaresSerializerField(result, field) and
    not exists(Class closer |
      closer = this.getAClassInHierarchy() and
      declaresSerializerField(closer, field) and
      result = closer.(ClassWithPointsTo).getClassObject().getASuperType().getPyClass()
    )
  }

  /** Holds if the declared serializer field is write-only. */
  predicate declaredFieldIsWriteOnly(string field) {
    exists(AssignStmt a, Keyword kw |
      a.getScope() = this and
      a.getATarget().(Name).getId() = field and
      kw = a.getValue().(Call).getAKeyword() and
      kw.getArg() = "write_only" and
      kw.getValue().(True).booleanValue() = true
    )
  }

  /** Holds if `field` is declared write-only on this serializer. */
  predicate isWriteOnly(string field) {
    exists(Class declaration |
      declaration = this.getFieldDeclaration(field) and
      declaration.(ModelSerializerClass).declaredFieldIsWriteOnly(field)
    )
    or
    // Meta.extra_kwargs applies only to automatically generated fields.
    not exists(this.getFieldDeclaration(field)) and
    exists(KeyValuePair outer, KeyValuePair inner |
      outer = this.getMetaValue("extra_kwargs").(Dict).getAnItem() and
      outer.getKey().(StringLiteral).getText() = field and
      inner = outer.getValue().(Dict).getAnItem() and
      inner.getKey().(StringLiteral).getText() = "write_only" and
      inner.getValue().(True).booleanValue() = true
    )
  }

  /** Holds if `field` is excluded via `Meta.exclude`. */
  predicate isExcluded(string field) {
    field = this.getMetaValue("exclude").getASubExpression().(StringLiteral).getText()
  }

  /** Gets the model class referenced by `Meta.model`, if it is defined in the analyzed code. */
  Class getModel() {
    exists(Import imp, Alias alias, ImportMember member |
      imp.getAName() = alias and
      imp.getScope() = this.getEnclosingModule() and
      member = alias.getValue().(ImportMember) and
      (
        exists(Name modelName |
          modelName = this.getMetaValue("model") and
          result.getName() = member.getName() and
          alias.getAsname().(Name).getId() = modelName.getId() and
          member.getModule().(ImportExpr).getImportedModuleName() = result.getEnclosingModule().getName()
        )
        or
        exists(Attribute modelAttribute |
          modelAttribute = this.getMetaValue("model") and
          modelAttribute.getName() = result.getName() and
          alias.getAsname().(Name).getId() = modelAttribute.getObject().(Name).getId() and
          member.getImportedModuleName() = result.getEnclosingModule().getName()
        )
      )
    )
    or
    exists(Import imp, Alias alias, ImportExpr moduleExpr |
      imp.getAName() = alias and
      imp.getScope() = this.getEnclosingModule() and
      moduleExpr = alias.getValue().(ImportExpr) and
      exists(Attribute modelAttribute |
        modelAttribute = this.getMetaValue("model") and
        modelAttribute.getName() = result.getName() and
        alias.getAsname().(Name).getId() = modelAttribute.getObject().(Name).getId() and
        moduleExpr.getImportedModuleName() = result.getEnclosingModule().getName()
      )
    )
  }
}

/** Holds if class `cls` declares a field named `field`. */
predicate declaresSerializerField(Class cls, string field) {
  exists(AssignStmt a |
    a.getScope() = cls and
    a.getATarget().(Name).getId() = field
  )
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
  (
    fields = ser.getMetaValue("fields") and
    (
      result = fields.(List).getAnElt().(StringLiteral).getText()
      or
      result = fields.(Tuple).getAnElt().(StringLiteral).getText()
      or
      fields.(StringLiteral).getText() = "__all__" and result = modelField(ser.getModel())
    )
    or
    fields = ser.getMetaValue("exclude") and
    not exists(ser.getMetaValue("fields")) and
    result = modelField(ser.getModel())
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
