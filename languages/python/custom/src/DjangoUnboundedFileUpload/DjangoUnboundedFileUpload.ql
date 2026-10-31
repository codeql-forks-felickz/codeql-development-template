/**
 * @name Django file upload field without a size validator
 * @description Django file upload fields without a recognizable file-size validator can accept
 *              arbitrarily large uploads, potentially exhausting application resources.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision low
 * @id py/django-unbounded-file-upload
 * @tags security
 *       external/cwe/cwe-400
 */

import python
import semmle.python.ApiGraphs

predicate isDjangoFileField(API::CallNode field) {
  field =
    API::moduleImport("django")
        .getMember("db")
        .getMember("models")
        .getMember(["FileField", "ImageField"])
        .getACall() and
  field.getNode().getNode().(Call).getScope() instanceof Class
}

predicate hasRecognizableSizeValidator(API::CallNode field) {
  exists(Name validatorName |
    validatorName = field.getArgByName("validators").asExpr().getASubExpression*() and
    validatorName.getId().toLowerCase().regexpMatch(".*(file|upload|max).*size.*")
  )
}

from API::CallNode field
where isDjangoFileField(field) and not hasRecognizableSizeValidator(field)
select field,
  "Django file upload field has no recognizable size validator, so large uploads may exhaust resources."
