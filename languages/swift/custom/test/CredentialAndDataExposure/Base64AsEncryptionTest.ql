import swift
import CredentialAndDataExposure.Base64AsEncryption
import utils.test.InlineExpectationsTest

module Base64AsEncryptionTest implements TestSig {
  string getARelevantTag() { result = "base64AsEncryption" }

  predicate hasActualResult(Location location, string element, string tag, string value) {
    exists(Base64EncodeCall call |
      base64AsEncryption(call, _) and
      location = call.getLocation() and
      element = call.toString() and
      tag = "base64AsEncryption" and
      value = ""
    )
  }
}

import MakeTest<Base64AsEncryptionTest>
