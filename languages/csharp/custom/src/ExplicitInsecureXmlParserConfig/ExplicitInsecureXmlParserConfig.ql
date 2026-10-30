/**
 * @name XML parser explicitly configured to resolve external entities
 * @description An XML parser that is explicitly configured to process DTDs and to use an
 *              unrestricted `XmlResolver` resolves external entities, which allows local file
 *              disclosure and server-side request forgery (XXE) if the XML is attacker-controlled.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.1
 * @precision medium
 * @id cs/xml/explicit-insecure-dtd-resolver
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 */

import csharp

/** Holds if `e` is a value for `XmlResolver` that does not restrict external entity resolution. */
predicate isUnrestrictedResolver(Expr e) {
  not e instanceof NullLiteral and
  not e.getType().(RefType).hasFullyQualifiedName("System.Xml", "XmlSecureResolver") and
  e.getType().(RefType).getABaseType*().hasFullyQualifiedName("System.Xml", "XmlResolver")
}

/** Holds if `e` is a value for `DtdProcessing` that enables DTD processing. */
predicate isDtdParse(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName("Parse") and
  e.getType().(Enum).hasFullyQualifiedName("System.Xml", "DtdProcessing")
}

/** Holds if `e` is a value for `DtdProcessing` that disables DTD processing. */
predicate isDtdDisabled(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName(["Prohibit", "Ignore"])
}

/**
 * Gets a value explicitly assigned to property `prop` of the object created by `create`,
 * either in an object initializer or via a local variable that holds the object.
 */
Expr getAValueForProp(ObjectCreation create, string prop) {
  exists(MemberInitializer init |
    init = create.getInitializer().(ObjectInitializer).getAMemberInitializer() and
    init.getLeftOperand().(PropertyAccess).getTarget().hasName(prop) and
    result = init.getRightOperand()
  )
  or
  exists(AssignExpr propAssign, PropertyAccess pa |
    pa = propAssign.getLeftOperand() and
    DataFlow::localExprFlow(create, pa.getQualifier()) and
    pa.getTarget().hasName(prop) and
    result = propAssign.getRightOperand()
  )
}

/** Holds if `settings` explicitly enables DTD processing and an unrestricted resolver. */
predicate insecureSettings(ObjectCreation settings, Expr dtd, Expr resolver) {
  settings.getObjectType().hasFullyQualifiedName("System.Xml", "XmlReaderSettings") and
  resolver = getAValueForProp(settings, "XmlResolver") and
  isUnrestrictedResolver(resolver) and
  (
    dtd = getAValueForProp(settings, "DtdProcessing") and isDtdParse(dtd)
    or
    dtd = getAValueForProp(settings, "ProhibitDtd") and dtd.(BoolLiteral).getBoolValue() = false
  )
}

module InsecureSettingsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { insecureSettings(source.asExpr(), _, _) }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System.Xml", "XmlReader", "Create") and
      sink.asExpr() = mc.getAnArgument() and
      sink.asExpr().getType().(RefType).hasFullyQualifiedName("System.Xml", "XmlReaderSettings")
    )
  }
}

module InsecureSettingsFlow = DataFlow::Global<InsecureSettingsConfig>;

from Call parser, Expr resolver, string kind
where
  exists(ObjectCreation settings, MethodCall create |
    create = parser and
    insecureSettings(settings, _, resolver) and
    InsecureSettingsFlow::flow(DataFlow::exprNode(settings),
      DataFlow::exprNode(create.getAnArgument())) and
    kind = "XmlReaderSettings with DtdProcessing.Parse"
  )
  or
  // `XmlTextReader` processes DTDs by default, so an unrestricted resolver is enough
  // unless DTD processing is explicitly disabled.
  parser.(ObjectCreation).getObjectType().hasFullyQualifiedName("System.Xml", "XmlTextReader") and
  resolver = getAValueForProp(parser, "XmlResolver") and
  isUnrestrictedResolver(resolver) and
  not exists(Expr dtd | dtd = getAValueForProp(parser, "DtdProcessing") | isDtdDisabled(dtd)) and
  not getAValueForProp(parser, "ProhibitDtd").(BoolLiteral).getBoolValue() = true and
  kind = "XmlTextReader with DTD processing enabled"
select parser, "This XML parser resolves external entities: " + kind + " and an unrestricted $@.",
  resolver, "XmlResolver"
