import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.StaticInitializationVector
import utils.test.InlineExpectationsTest

module StaticIvTest implements TestSig {
  string getARelevantTag() { result = "staticIv" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      ExtendedStaticInitializationVectorFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "staticIv" and
      value = ""
    )
  }
}

import MakeTest<StaticIvTest>
