import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.HardcodedEncryptionKey
import utils.test.InlineExpectationsTest

module HardcodedKeyTest implements TestSig {
  string getARelevantTag() { result = "hardcodedKey" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      ExtendedHardcodedKeyFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "hardcodedKey" and
      value = ""
    )
  }
}

import MakeTest<HardcodedKeyTest>
