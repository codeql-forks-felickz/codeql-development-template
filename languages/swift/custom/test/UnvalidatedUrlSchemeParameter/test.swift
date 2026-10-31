// --- stubs ---

struct URL {
  init?(string: String) {}
  var scheme: String? { get { return nil } }
  var host: String? { get { return nil } }
  var query: String? { get { return nil } }
  var absoluteString: String { get { return "" } }
}

struct URLQueryItem {
  var name: String
  var value: String?
}

struct URLComponents {
  init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}
  var queryItems: [URLQueryItem]? { get { return nil } }
}

class UIResponder {}
class UIViewController : UIResponder {}

class UIApplication {
  struct OpenURLOptionsKey : Hashable {
    let rawValue: String
  }
  struct LaunchOptionsKey : Hashable {
    let rawValue: String
  }
  struct OpenExternalURLOptionsKey : Hashable {
    let rawValue: String
  }
  static var shared: UIApplication { get { return UIApplication() } }
  func open(_ url: URL, options: [UIApplication.OpenExternalURLOptionsKey : Any] = [:], completionHandler completion: ((Bool) -> Void)? = nil) {}
}

protocol UIApplicationDelegate {
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any]) -> Bool
}

class UIAlertController : UIViewController {
  enum Style { case actionSheet, alert }
  init(title: String?, message: String?, preferredStyle: UIAlertController.Style) {}
}

class MFMessageComposeViewController : UIViewController {
  var recipients: [String]?
  var body: String?
}

class MFMailComposeViewController : UIViewController {
  func setToRecipients(_ toRecipients: [String]?) {}
  func setSubject(_ subject: String) {}
  func setMessageBody(_ body: String, isHTML: Bool) {}
}

class UIScene : UIResponder {
  class ConnectionOptions {
    var urlContexts: Set<UIOpenURLContext> { get { return [] } }
  }
}

class UISceneSession {}

class UIOpenURLContext : Hashable {
  var url: URL { get { return URL(string: "")! } }
  static func == (lhs: UIOpenURLContext, rhs: UIOpenURLContext) -> Bool { return lhs === rhs }
  func hash(into hasher: inout Hasher) {}
}

protocol UISceneDelegate {
  func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions)
  func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>)
}

// --- helpers (mirroring common app extensions) ---

extension URL {
  var parametersInfo: [AnyHashable: Any]? {
    let urlComponents = URLComponents(url: self, resolvingAgainstBaseURL: false)
    let queryItems = urlComponents?.queryItems
    var queryStringDictionary = [String: String]()
    for queryItem: URLQueryItem? in queryItems ?? [URLQueryItem?]() {
      if let name = queryItem?.name {
        let value = queryItem?.value != nil ? queryItem?.value : ""
        queryStringDictionary[name] = value
      }
    }
    return queryStringDictionary
  }
}

extension UIAlertController {
  class func showAlertWith(title: String, message: String) -> UIAlertController {
    let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert) // $ Alert
    return alertController
  }
}

func isValidPhoneNumber(_ number: String) -> Bool {
  return number.allSatisfy { $0.isNumber } && number.count <= 15
}

let allowedMessages = ["Hello", "Goodbye"]

// --- tests ---

class AppDelegate1 : UIResponder, UIApplicationDelegate {
  // BAD: only the scheme is checked; query parameters are used as-is.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool { // $ Source
    if url.scheme == "igoat", let queryInfo = url.parametersInfo {
      let mobileNo = queryInfo["contactNumber"] ?? ""
      let message = queryInfo["message"] ?? ""
      _ = UIAlertController.showAlertWith(title: "iGoat", message: "Message \"\(message)\" sent to \(mobileNo)")
      return true
    }
    return false
  }
}

class AppDelegate2 : UIResponder, UIApplicationDelegate {
  // BAD: query items drive an SMS composer and an outgoing URL open.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool { // $ Source
    guard let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else {
      return false
    }
    let number = items.first?.value ?? ""
    let text = items.last?.value ?? ""
    let composer = MFMessageComposeViewController()
    composer.recipients = [number] // $ Alert
    composer.body = text // $ Alert
    if let target = URL(string: "tel:" + number) {
      UIApplication.shared.open(target) // $ Alert
    }
    return true
  }
}

class AppDelegate3 : UIResponder, UIApplicationDelegate {
  // GOOD: each parameter is validated before use.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    guard url.scheme == "igoat", let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else {
      return false
    }
    let number = items.first?.value ?? ""
    let text = items.last?.value ?? ""
    guard isValidPhoneNumber(number) else {
      return false
    }
    if !allowedMessages.contains(text) {
      return false
    }
    let composer = MFMessageComposeViewController()
    composer.recipients = [number]
    composer.body = text
    _ = UIAlertController(title: "Sent", message: text + " sent to " + number, preferredStyle: .alert)
    return true
  }
}

class AppDelegate4 : UIResponder, UIApplicationDelegate {
  // GOOD: the URL contents are not used in a sensitive sink.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    _ = UIAlertController(title: "iGoat", message: "Link opened", preferredStyle: .alert)
    return url.scheme == "igoat"
  }
}

class NotADelegate {
  // GOOD: not a custom URL scheme handler.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    _ = UIAlertController(title: "Info", message: url.absoluteString, preferredStyle: .alert)
    return true
  }
}

class AppDelegate5 : UIResponder, UIApplicationDelegate {
  // BAD: the phone number is validated, but the mail body is not.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool { // $ Source
    let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
    let number = items.first?.value ?? ""
    let body = items.last?.value ?? ""
    if isValidPhoneNumber(number) {
      let mail = MFMailComposeViewController()
      mail.setSubject("Call " + number)
      mail.setMessageBody(body, isHTML: true) // $ Alert
    }
    return true
  }
}

class SceneDelegate1 : UIResponder, UISceneDelegate {
  // BAD: URL contexts delivered to a scene are used without validation.
  func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) { // $ Source
    for context in URLContexts {
      let query = context.url.query ?? ""
      _ = UIAlertController(title: "Link", message: query, preferredStyle: .alert) // $ Alert
    }
  }

  // BAD: URL contexts delivered when the scene is first connected.
  func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) { // $ Source
    if let context = connectionOptions.urlContexts.first {
      UIApplication.shared.open(context.url) // $ Alert
    }
  }
}

class AppDelegate6 : UIResponder, UIApplicationDelegate {
  // BAD: parsing the URL is not validation, and the failed-validation branch uses the value.
  func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool { // $ Source
    guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
      return false
    }
    let number = comps.queryItems?.first?.value ?? ""
    guard isValidPhoneNumber(number) else {
      _ = UIAlertController(title: "Invalid number", message: number, preferredStyle: .alert) // $ Alert
      return false
    }
    if number != "112" {
      UIApplication.shared.open(url) // $ Alert
    } else {
      _ = UIAlertController(title: "Calling", message: number, preferredStyle: .alert)
    }
    return true
  }
}
