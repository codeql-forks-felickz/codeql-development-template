/**
 * @name Arbitrary file access during archive extraction ("Zip Slip") with extended models
 * @description Extracting files from a malicious ZIP file, or similar type of archive, without
 *              validating that the destination file path is within the destination directory
 *              can allow an attacker to unexpectedly gain access to resources. This variant of
 *              `js/zipslip` additionally models `unzipper.Open` central directories and
 *              extraction with vulnerable versions of `adm-zip`.
 * @kind path-problem
 * @id js/zipslip-extended
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 */

import javascript
import semmle.javascript.security.dataflow.ZipSlipQuery
import ZipSlipExtensions
import DataFlow::DeduplicatePathGraph<ZipSlipFlow::PathNode, ZipSlipFlow::PathGraph>

from PathNode source, PathNode sink
where ZipSlipFlow::flowPath(source.getAnOriginalPathNode(), sink.getAnOriginalPathNode())
select source.getNode(), source, sink,
  "Unsanitized archive entry, which may contain '..', is used in a $@.", sink.getNode(),
  "file system operation"
