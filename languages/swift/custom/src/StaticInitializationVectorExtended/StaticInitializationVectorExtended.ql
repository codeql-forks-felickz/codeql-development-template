/**
 * @name Static initialization vector for encryption (extended)
 * @description Using a static initialization vector (IV) for encryption is not secure. This
 *              extends `swift/static-initialization-vector` with CommonCrypto IV arguments,
 *              `nil` IVs (which CommonCrypto replaces with all zero bytes) and IVs that come
 *              from a default parameter value.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id swift/custom/static-initialization-vector-extended
 * @tags security
 *       external/cwe/cwe-329
 *       external/cwe/cwe-1204
 */

import swift
import StaticInitializationVectorExtended
import StaticInitializationVectorExtendedFlow::PathGraph

from
  StaticInitializationVectorExtendedFlow::PathNode sourceNode,
  StaticInitializationVectorExtendedFlow::PathNode sinkNode, string message
where staticInitializationVectorExtended(sourceNode, sinkNode, message)
select sinkNode.getNode(), sourceNode, sinkNode, message
