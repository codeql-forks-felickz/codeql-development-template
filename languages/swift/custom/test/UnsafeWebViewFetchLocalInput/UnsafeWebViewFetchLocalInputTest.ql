import swift
import UnsafeWebViewFetchLocalInput.UnsafeWebViewFetchLocalInput
import utils.test.InlineExpectationsTest

module UnsafeWebViewFetchLocalInputTest implements TestSig {
  string getARelevantTag() { result = "unsafeWebViewFetchLocalInput" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(UnsafeWebViewFetchSink sink |
      unsafeWebViewFetchLocalInput(sink, _) and
      location = sink.getLocation() and
      element = sink.toString() and
      tag = "unsafeWebViewFetchLocalInput" and
      value = ""
    )
  }
}

import MakeTest<UnsafeWebViewFetchLocalInputTest>
