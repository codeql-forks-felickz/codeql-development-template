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

  func submitName() throws {
    let info = ["firstName": firstNameField.text]
    let jsonData = try JSONSerialization.data(withJSONObject: info, options: .prettyPrinted)
    // GOOD: not sensitive
    var request = URLRequest(url: URL(string: userUrl)!)
    request.httpBody = jsonData
    URLSession.shared.dataTask(with: request, completionHandler: { _, _, _ in }).resume()
  }
}
