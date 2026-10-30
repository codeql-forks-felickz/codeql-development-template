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
  exists(Expr value |
    DataFlow::localExprFlow(value, e) and
    not (value = e and e instanceof LocalVariableAccess) and
    not value instanceof NullLiteral and
    not value.getType().(RefType).hasFullyQualifiedName("System.Xml", "XmlSecureResolver") and
    value.getType().(RefType).getABaseType*().hasFullyQualifiedName("System.Xml", "XmlResolver")
  )
}

/** Holds if `e` is a value for `DtdProcessing` that enables DTD processing. */
predicate isDtdParse(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName("Parse") and
  e.getType().(Enum).hasFullyQualifiedName("System.Xml", "DtdProcessing")
}

/** Holds if `e` is a value for `DtdProcessing` that disables DTD processing. */
predicate isDtdDisabled(Expr e) {
  e.(FieldAccess).getTarget().(EnumConstant).hasName(["Prohibit", "Ignore"]) or
  e.(BoolLiteral).getBoolValue() = true
}

/** Holds if `write` assigns `prop` on the object created by `create`. */
private predicate writesProperty(ObjectCreation create, string prop, AssignExpr write) {
  exists(MemberInitializer init |
    init = write and
    init = create.getInitializer().(ObjectInitializer).getAMemberInitializer() and
    init.getLeftOperand().(PropertyAccess).getTarget().hasName(prop)
  )
  or
  exists(PropertyAccess access |
    access = write.getLeftOperand() and
    DataFlow::localExprFlow(create, access.getQualifier()) and
    access.getTarget().hasName(prop)
  )
}

/**
 * Gets a value assigned to property `prop` that is not overwritten before `end`.
 * `end` is either the reader creation/use or a return of the settings object.
 */
Expr getAValueForProp(ObjectCreation create, string prop, ControlFlowElement end) {
  exists(AssignExpr write |
    writesProperty(create, prop, write) and
    end.reachableFrom(write) and
    not exists(AssignExpr later |
      writesProperty(create, prop, later) and
      later.reachableFrom(write) and
      end.reachableFrom(later)
    ) and
    result = write.getRightOperand()
  )
}

/** Gets the effective value of either DTD-processing setting at `end`. */
Expr getAValueForDtdProp(ObjectCreation create, ControlFlowElement end) {
  exists(AssignExpr write |
    (
      writesProperty(create, "DtdProcessing", write) or
      writesProperty(create, "ProhibitDtd", write)
    ) and
    end.reachableFrom(write) and
    not exists(AssignExpr later |
      (
        writesProperty(create, "DtdProcessing", later) or
        writesProperty(create, "ProhibitDtd", later)
      ) and
      later.reachableFrom(write) and
      end.reachableFrom(later)
    ) and
    result = write.getRightOperand()
  )
}

/** Gets a point at which the configuration of `create` is observed. */
private ControlFlowElement getAConfigurationEnd(ObjectCreation create, ControlFlowElement use) {
  use.getEnclosingCallable() = create.getEnclosingCallable() and
  result = use
  or
  exists(ReturnStmt ret |
    use.getEnclosingCallable() != create.getEnclosingCallable() and
    ret.getEnclosingCallable() = create.getEnclosingCallable() and
    DataFlow::localExprFlow(create, ret.getExpr()) and
    result = ret
  )
}

/** Holds if `settings` explicitly enables DTD processing and an unrestricted resolver. */
predicate insecureSettings(ObjectCreation settings, ControlFlowElement use, Expr dtd, Expr resolver) {
  settings.getObjectType().hasFullyQualifiedName("System.Xml", "XmlReaderSettings") and
  exists(ControlFlowElement end |
    end = getAConfigurationEnd(settings, use) and
    resolver = getAValueForProp(settings, "XmlResolver", end) and
    isUnrestrictedResolver(resolver) and
    (
      dtd = getAValueForDtdProp(settings, end) and isDtdParse(dtd)
      or
      dtd = getAValueForDtdProp(settings, end) and
      dtd.(BoolLiteral).getBoolValue() = false
    )
  )
}

module InsecureSettingsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall create |
      create.getTarget().hasFullyQualifiedName("System.Xml", "XmlReader", "Create") and
      insecureSettings(source.asExpr(), create, _, _)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getTarget().hasFullyQualifiedName("System.Xml", "XmlReader", "Create") and
      not exists(Expr firstArg |
        firstArg = mc.getArgument(0) and
        firstArg
            .getType()
            .(RefType)
            .getABaseType*()
            .hasFullyQualifiedName("System.Xml", "XmlReader")
      ) and
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
    insecureSettings(settings, create, _, resolver) and
    InsecureSettingsFlow::flow(DataFlow::exprNode(settings),
      DataFlow::exprNode(create.getAnArgument())) and
    kind = "XmlReaderSettings with DtdProcessing.Parse"
  )
  or
  // `XmlTextReader` processes DTDs by default, so an unrestricted resolver is enough
  // unless DTD processing is explicitly disabled.
  parser.(ObjectCreation).getObjectType().hasFullyQualifiedName("System.Xml", "XmlTextReader") and
  exists(MethodCall read |
    DataFlow::localExprFlow(parser, read.getQualifier()) and
    read.getTarget().getName() in ["Read", "ReadAsync"] and
    read.getQualifier()
        .getType()
        .(RefType)
        .getABaseType*()
        .hasFullyQualifiedName("System.Xml", "XmlTextReader") and
    resolver = getAValueForProp(parser, "XmlResolver", read) and
    isUnrestrictedResolver(resolver) and
    not exists(Expr dtd | dtd = getAValueForDtdProp(parser, read) and isDtdDisabled(dtd)) and
    kind = "XmlTextReader with DTD processing enabled"
  )
select parser, "This XML parser resolves external entities: " + kind + " and an unrestricted $@.",
  resolver, "XmlResolver"
