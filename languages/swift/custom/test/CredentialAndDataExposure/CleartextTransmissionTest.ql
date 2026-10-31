import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.CleartextTransmission
import utils.test.InlineExpectationsTest

module CleartextTransmissionTest implements TestSig {
  string getARelevantTag() { result = "cleartextTransmission" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      ExtendedCleartextTransmissionFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "cleartextTransmission" and
      value = ""
    )
  }
}

import MakeTest<CleartextTransmissionTest>
