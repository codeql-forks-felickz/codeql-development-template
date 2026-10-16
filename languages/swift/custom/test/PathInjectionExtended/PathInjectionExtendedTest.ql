import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.security.PathInjectionQuery
import PathInjectionExtended.PathInjectionModels
import utils.test.InlineExpectationsTest

module PathInjectionExtendedTest implements TestSig {
  string getARelevantTag() { result = "hasPathInjection" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(DataFlow::Node sink |
      PathInjectionFlow::flowTo(sink) and
      location = sink.getLocation() and
      location.getFile().getBaseName() != "" and
      element = sink.toString() and
      tag = "hasPathInjection" and
      value = ""
    )
  }
}

import MakeTest<PathInjectionExtendedTest>
