/**
 * @name Apache HttpClient TLS validation disabled
 * @description Using `NoopHostnameVerifier`, `AllowAllHostnameVerifier`,
 *              `TrustSelfSignedStrategy`, `TrustAllStrategy` or a trust strategy that always
 *              returns `true` with Apache HttpClient disables certificate or hostname
 *              validation, so an attacker who can intercept the connection can impersonate
 *              the server.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/apache-httpclient-insecure-tls
 * @tags security
 *       external/cwe/cwe-295
 *       external/cwe/cwe-297
 */

import java

/** Gets an Apache HttpClient 4.x or 5.x package that contains TLS helper classes. */
string apacheSslPackage() {
  result =
    [
      "org.apache.http.conn.ssl", "org.apache.http.ssl", "org.apache.hc.client5.http.ssl",
      "org.apache.hc.core5.ssl"
    ]
}

/** A hostname verifier from Apache HttpClient that accepts every hostname. */
class AcceptAllHostnameVerifier extends Class {
  AcceptAllHostnameVerifier() {
    this.hasQualifiedName(apacheSslPackage(), ["NoopHostnameVerifier", "AllowAllHostnameVerifier"])
  }
}

/** A trust strategy from Apache HttpClient that trusts self-signed or all certificates. */
class InsecureTrustStrategy extends Class {
  InsecureTrustStrategy() {
    this.hasQualifiedName(apacheSslPackage(), ["TrustSelfSignedStrategy", "TrustAllStrategy"])
  }
}

/** An Apache HttpClient class that defines an insecure hostname verifier or trust strategy. */
class ApacheSslClass extends Class {
  ApacheSslClass() {
    this instanceof AcceptAllHostnameVerifier or
    this instanceof InsecureTrustStrategy or
    this.hasQualifiedName(apacheSslPackage(), "SSLConnectionSocketFactory")
  }
}

/** The Apache HttpClient `TrustStrategy` interface. */
class TrustStrategy extends Interface {
  TrustStrategy() { this.hasQualifiedName(apacheSslPackage(), "TrustStrategy") }
}

/** An `isTrusted` method from source that implements `TrustStrategy` and always returns `true`. */
class TrustAllIsTrustedMethod extends Method {
  TrustAllIsTrustedMethod() {
    this.fromSource() and
    this.hasName("isTrusted") and
    this.getDeclaringType().getASupertype+() instanceof TrustStrategy and
    not this.getDeclaringType() instanceof InsecureTrustStrategy and
    exists(ReturnStmt ret | ret.getEnclosingCallable() = this) and
    forall(ReturnStmt ret | ret.getEnclosingCallable() = this |
      ret.getExpr().(BooleanLiteral).getBooleanValue() = true
    )
  }
}

/** Gets a description of the certificates accepted by the insecure trust strategy `t`. */
string describeAcceptedCertificates(InsecureTrustStrategy t) {
  if t.hasName("TrustSelfSignedStrategy")
  then result = "any self-signed certificate"
  else result = "any certificate"
}

/** Holds if `e` creates or reads a hostname verifier that accepts any hostname. */
predicate isAcceptAllHostnameVerifier(Expr e) {
  e.(ClassInstanceExpr).getConstructedType() instanceof AcceptAllHostnameVerifier
  or
  exists(Field f | f = e.(FieldAccess).getField() |
    f.getDeclaringType() instanceof AcceptAllHostnameVerifier and f.hasName("INSTANCE")
    or
    f.getDeclaringType().hasQualifiedName("org.apache.http.conn.ssl", "SSLConnectionSocketFactory") and
    f.hasName("ALLOW_ALL_HOSTNAME_VERIFIER")
  )
}

/** Holds if `e` creates or reads a built-in insecure trust strategy. */
predicate isInsecureTrustStrategy(Expr e) {
  e.(ClassInstanceExpr).getConstructedType() instanceof InsecureTrustStrategy
  or
  exists(Field f | f = e.(FieldAccess).getField() |
    f.getDeclaringType() instanceof InsecureTrustStrategy and f.hasName("INSTANCE")
  )
}

/** Holds if `e` creates a trust strategy from source that always returns `true`. */
predicate isTrustAllStrategy(Expr e) {
  e.(ClassInstanceExpr).getConstructedType().getAMethod() instanceof TrustAllIsTrustedMethod
  or
  e.(LambdaExpr).asMethod() instanceof TrustAllIsTrustedMethod
  or
  e.(LambdaExpr).getAnonymousClass().getASupertype() instanceof TrustStrategy and
  e.(LambdaExpr).getExprBody().(BooleanLiteral).getBooleanValue() = true
}

from Expr e, string message
where
  // Exclude the definitions of the Apache classes themselves.
  not e.getEnclosingCallable().getDeclaringType() instanceof ApacheSslClass and
  (
    isAcceptAllHostnameVerifier(e) and
    message = "This hostname verifier accepts any hostname, disabling hostname verification."
    or
    isInsecureTrustStrategy(e) and
    message =
      "This trust strategy accepts " + describeAcceptedCertificates(e.getType()) +
        ", disabling certificate validation."
    or
    isTrustAllStrategy(e) and
    message = "This trust strategy accepts any certificate, disabling certificate validation."
  )
select e, message
