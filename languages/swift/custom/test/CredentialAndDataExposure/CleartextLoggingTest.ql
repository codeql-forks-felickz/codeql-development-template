import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.CleartextLogging
import utils.test.InlineExpectationsTest

module CleartextLoggingTest implements TestSig {
  string getARelevantTag() { result = "cleartextLogging" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      ExtendedCleartextLoggingFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "cleartextLogging" and
      value = ""
    )
  }
}

import MakeTest<CleartextLoggingTest>
