// CWE-319: a password wrapped in a request model that is sent with Alamofire.

struct SignInModel: Encodable {
  let email: String
  let password: String
}

struct SearchModel: Encodable {
  let query: String
}

class NetworkCalls {
  func auth(_ info: SignInModel) {
    _ = AF.request("http://example.com/", method: .post, parameters: info) // $ cleartextTransmission
  }

  func search(_ model: SearchModel) {
    // GOOD: no sensitive data
    _ = AF.request("http://example.com/", method: .post, parameters: model)
  }
}

func signIn(withEmail email: String, password: String) {
  NetworkCalls().auth(SignInModel(email: email, password: password))
}

func search(text: String) {
  NetworkCalls().search(SearchModel(query: text))
}
