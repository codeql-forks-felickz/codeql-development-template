/**
 * @name Static initialization vector for encryption (extended)
 * @description Using a static initialization vector (IV) for encryption is not secure. To maximize encryption and prevent
 *              dictionary attacks, IVs should be unique and unpredictable. This variant also covers the CommonCrypto API
 *              (`CCCrypt`, `CCCryptorCreate`) and IVs stored in global constants or property initializers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id swift/custom/static-initialization-vector
 * @tags security
 *       external/cwe/cwe-329
 *       external/cwe/cwe-1204
 */

import swift
import CredentialAndDataExposure.StaticInitializationVector
import ExtendedStaticInitializationVectorFlow::PathGraph

from
  ExtendedStaticInitializationVectorFlow::PathNode source,
  ExtendedStaticInitializationVectorFlow::PathNode sink, Expr origin
where
  ExtendedStaticInitializationVectorFlow::flowPath(source, sink) and
  isStaticIvSource(source.getNode(), origin)
select sink.getNode(), source, sink,
  "The static value $@ is used as an initialization vector for encryption.", origin,
  origin.toString()
