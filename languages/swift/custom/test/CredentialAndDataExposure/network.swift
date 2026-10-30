// CWE-319: a password wrapped in a request model that is sent with Alamofire.

struct SignInModel: Encodable {
  let email: String
  let password: String
}

struct SearchModel: Encodable {
  let query: String
}

struct ExplicitSignInModel: Encodable {
  let password: String

  init(password: String) {
    self.password = password
  }
}

struct DiscardedPasswordModel: Encodable {
  let ok = true

  init(password: String) {}
}

class NetworkCalls {
  func auth(_ info: SignInModel) {
    _ = AF.request("http://example.com/", method: .post, parameters: info) // $ cleartextTransmission
  }

  func explicitAuth(password: String) {
    let model = ExplicitSignInModel(password: password)
    _ = AF.request("http://example.com/", method: .post, parameters: model) // $ cleartextTransmission
  }

  func discardedPassword(password: String) {
    // GOOD: the explicit initializer discards the password.
    let model = DiscardedPasswordModel(password: password)
    _ = AF.request("http://example.com/", method: .post, parameters: model)
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

// CWE-319: a Social Security number from a text field sent in the body of a
// request to an `http://` URL.

class ServerCommunicationViewController: UIViewController {
  var firstNameField = UITextField()
  var ssnField = UITextField()

  let userUrl = "http://localhost:8080/igoat/user"
  let secureUserUrl = "https://localhost:8443/igoat/user"

  func submit() throws {
    let accountInfo = ["firstName": firstNameField.text, "socialSecurityNumber": ssnField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: accountInfo, options: .prettyPrinted)
    var request = URLRequest(url: URL(string: userUrl)!)
    request.httpMethod = "POST"
    request.httpBody = jsonData // $ cleartextTransmission
    URLSession.shared.dataTask(with: request, completionHandler: { _, _, _ in }).resume()
  }

  func submitSecurely() throws {
    let accountInfo = ["firstName": firstNameField.text, "socialSecurityNumber": ssnField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: accountInfo, options: .prettyPrinted)
    // GOOD: HTTPS
    var request = URLRequest(url: URL(string: secureUserUrl)!)
    request.httpBody = jsonData
    URLSession.shared.dataTask(with: request, completionHandler: { _, _, _ in }).resume()
  }

  func submitAfterSecureReassignment() throws {
    let accountInfo = ["socialSecurityNumber": ssnField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: accountInfo, options: .prettyPrinted)
    var request = URLRequest(url: URL(string: userUrl)!)
    request = URLRequest(url: URL(string: secureUserUrl)!)
    // GOOD: the request was replaced with an HTTPS request before the body is written.
    request.httpBody = jsonData
  }

  func submitAfterHttpBranchMerge() throws {
    let accountInfo = ["socialSecurityNumber": ssnField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: accountInfo, options: .prettyPrinted)
    var request = URLRequest(url: URL(string: secureUserUrl)!)
    if firstNameField.text != nil {
      request = URLRequest(url: URL(string: userUrl)!)
    } else {
      request = URLRequest(url: URL(string: userUrl)!)
    }
    request.httpBody = jsonData // $ cleartextTransmission
  }

  func submitName() throws {
    let info = ["firstName": firstNameField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: info, options: .prettyPrinted)
    // GOOD: not sensitive
    var request = URLRequest(url: URL(string: userUrl)!)
    request.httpBody = jsonData
    URLSession.shared.dataTask(with: request, completionHandler: { _, _, _ in }).resume()
  }
}
