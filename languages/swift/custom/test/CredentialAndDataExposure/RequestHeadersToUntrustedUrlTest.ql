import swift
import codeql.swift.dataflow.DataFlow
import CredentialAndDataExposure.RequestHeadersToUntrustedUrl
import utils.test.InlineExpectationsTest

module HeadersToUntrustedUrlTest implements TestSig {
  string getARelevantTag() { result = "headersToUntrustedUrl" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      RequestHeadersToUntrustedUrlFlow::flowTo(sink) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "headersToUntrustedUrl" and
      value = ""
    )
  }
}

import MakeTest<HeadersToUntrustedUrlTest>
