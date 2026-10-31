import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.EncryptionKeyFromCleartextHttp
import utils.test.InlineExpectationsTest

module EncryptionKeyFromCleartextHttpTest implements TestSig {
  string getARelevantTag() { result = "keyFromCleartextHttp" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      EncryptionKeyFromCleartextHttpFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "keyFromCleartextHttp" and
      value = ""
    )
  }
}

import MakeTest<EncryptionKeyFromCleartextHttpTest>
