import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.CleartextStorageDatabase
import utils.test.InlineExpectationsTest

module CleartextStorageTest implements TestSig {
  string getARelevantTag() { result = "cleartextStorage" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      ExtendedCleartextStorageDatabaseFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "cleartextStorage" and
      value = ""
    )
  }
}

import MakeTest<CleartextStorageTest>
