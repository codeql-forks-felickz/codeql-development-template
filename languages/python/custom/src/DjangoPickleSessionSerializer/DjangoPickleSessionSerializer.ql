/**
 * @name Django signed-cookie sessions deserialized with pickle
 * @description Configuring Django to store sessions in signed cookies while using
 *              `PickleSerializer` deserializes client-supplied cookie data with `pickle`,
 *              which allows arbitrary code execution if the signing key is known or leaked.
 * @kind problem
 * @id py/custom/django-pickle-session-serializer
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags external/cwe/cwe-502
 *       security
 *       serialization
 *       django
 */

import python

/**
 * Holds if `assign` is a module-level assignment in `m` of the string literal `value`
 * to the setting `name`.
 */
predicate settingAssignment(Module m, string name, string value, AssignStmt assign) {
  assign.getScope() = m and
  assign.getATarget().(Name).getId() = name and
  assign.getValue().(StringLiteral).getText() = value
}

from Module m, AssignStmt serializer, AssignStmt engine
where
  settingAssignment(m, "SESSION_SERIALIZER", "django.contrib.sessions.serializers.PickleSerializer",
    serializer) and
  settingAssignment(m, "SESSION_ENGINE", "django.contrib.sessions.backends.signed_cookies", engine)
select serializer,
  "Django sessions are deserialized with PickleSerializer while using the $@, so client-controlled cookie data is unpickled.",
  engine, "signed-cookie session backend"
