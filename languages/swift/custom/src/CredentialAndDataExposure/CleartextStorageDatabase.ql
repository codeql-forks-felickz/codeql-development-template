/**
 * @name Cleartext storage of sensitive information in a local database (extended)
 * @description Storing sensitive information in a non-encrypted database can expose it to an attacker.
 *              This variant also recognizes writes to Core Data objects created with
 *              `NSEntityDescription.insertNewObject(forEntityName:into:)` when the managed object class
 *              cannot be resolved, writes to Objective-C Realm (`RLMObject`) objects, and hard-coded values
 *              written to properties with sensitive names.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id swift/custom/cleartext-storage-database
 * @tags security
 *       external/cwe/cwe-312
 */

import swift
import CredentialAndDataExposure.CleartextStorageDatabase
import ExtendedCleartextStorageDatabaseFlow::PathGraph

from
  ExtendedCleartextStorageDatabaseFlow::PathNode source,
  ExtendedCleartextStorageDatabaseFlow::PathNode sink
where ExtendedCleartextStorageDatabaseFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This operation stores '" + sink.getNode().toString() +
    "' in a database. It may contain unencrypted sensitive data from $@.", source,
  source.getNode().toString()
