/**
 * @name Certificate validation callback accepts any certificate
 * @description A server certificate validation callback that unconditionally returns
 *              `true` disables TLS certificate validation, allowing an attacker who can
 *              intercept traffic to impersonate the remote endpoint.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id cs/unsafe-certificate-validation-callback
 * @tags security
 *       external/cwe/cwe-295
 */

import csharp
import semmle.code.csharp.dataflow.DataFlow

/** Holds if every value that callable `c` can return is the constant `true`. */
predicate alwaysReturnsTrue(Callable c) {
  forex(Expr ret | c.canReturn(ret) | ret.getValue() = "true")
}

/**
 * Holds if `e` evaluates to a delegate that accepts any certificate.
 */
predicate acceptsAnyCertificate(Expr e) {
  alwaysReturnsTrue(e.(AnonymousFunctionExpr))
  or
  alwaysReturnsTrue(e.(CallableAccess).getTarget())
  or
  e.(PropertyAccess)
      .getTarget()
      .hasFullyQualifiedName("System.Net.Http", "HttpClientHandler",
        "DangerousAcceptAnyServerCertificateValidator")
  or
  acceptsAnyCertificate(e.(DelegateCreation).getArgument())
  or
  exists(Expr src |
    acceptsAnyCertificate(src) and
    src != e and
    DataFlow::localExprFlow(src, e)
  )
}

/**
 * Holds if `e` is used as a server certificate validation callback, either by
 * assigning it to a certificate validation callback property, or by passing it
 * as a `RemoteCertificateValidationCallback` argument.
 */
predicate isCertificateValidationCallback(Expr e) {
  exists(AssignableDefinition def |
    def.getSource() = e and
    def.getTarget()
        .(Property)
        .hasName([
            "ServerCertificateValidationCallback", "ServerCertificateCustomValidationCallback",
            "RemoteCertificateValidationCallback"
          ])
  )
  or
  exists(AssignAddExpr add |
    add.getRightOperand() = e and
    add.getLeftOperand()
        .(PropertyAccess)
        .getTarget()
        .hasName(["ServerCertificateValidationCallback", "RemoteCertificateValidationCallback"])
  )
  or
  exists(Call call, Parameter p |
    e = call.getArgumentForParameter(p) and
    p.getType().hasFullyQualifiedName("System.Net.Security", "RemoteCertificateValidationCallback")
  )
}

from Expr e
where
  isCertificateValidationCallback(e) and
  acceptsAnyCertificate(e)
select e,
  "This certificate validation callback unconditionally returns true, so any server certificate is accepted."
