// --- stubs ---

class NSObject {}

class UIResponder : NSObject {}

class UIView : UIResponder {}

class UIWindow : UIView {}

class UIViewController : UIResponder {}

class UITextField : UIView {
  var text: String?
  var isSecureTextEntry: Bool = false
}

class UIApplication : NSObject {
}

protocol UIApplicationDelegate {}

class UIPasteboard : NSObject {
  struct OptionsKey : Hashable {
    let rawValue: String
    static let expirationDate = OptionsKey(rawValue: "expirationDate")
    static let localOnly = OptionsKey(rawValue: "localOnly")
  }

  class var general: UIPasteboard { return UIPasteboard() }

  var string: String?
  var strings: [String]?
  var items: [[String : Any]] = []

  func setValue(_ value: Any, forPasteboardType pasteboardType: String) {}
  func setItems(_ items: [[String : Any]], options: [UIPasteboard.OptionsKey : Any] = [:]) {}
  func addItems(_ items: [[String : Any]]) {}
}

struct Date {
  init(timeIntervalSinceNow: Double) {}
}

struct URL {
  init?(string: String) {}
}

struct Data {}

extension String {
  func data(using encoding: Int) -> Data? { return Data() }
}

struct URLRequest {
  enum CachePolicy {
    case useProtocolCachePolicy
    case reloadIgnoringLocalCacheData
    case returnCacheDataElseLoad
    case returnCacheDataDontLoad
  }

  init(url: URL, cachePolicy: CachePolicy = .useProtocolCachePolicy, timeoutInterval: Double = 60.0) {}

  var cachePolicy: CachePolicy = .useProtocolCachePolicy
  var httpBody: Data?
}

typealias OSStatus = Int32
typealias CFDictionary = [String : Any]

let kSecClass: String = "class"
let kSecClassGenericPassword: String = "genp"
let kSecAttrAccount: String = "acct"
let kSecValueData: String = "v_Data"

func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<AnyObject?>?) -> OSStatus { return 0 }

class Crypto {
  static func encrypt(_ data: String) -> String { return data }
}

func decryptString(_ value: String) -> String { return value }

// --- pasteboard ---

class SecretItemViewController : UIViewController {
  var decryptedValue: String = ""
  var itemName: String = ""

  func copyValue() {
    let pb: UIPasteboard = UIPasteboard.general
    pb.string = self.decryptedValue // $ Alert[swift/credential-and-data-exposure]
  }

  func copyName() {
    UIPasteboard.general.string = itemName // GOOD (not sensitive)
  }

  func copyPassword(password: String) {
    UIPasteboard.general.setValue(password, forPasteboardType: "public.text") // $ Alert[swift/credential-and-data-exposure]
    UIPasteboard.general.addItems([["public.text": password]]) // $ Alert[swift/credential-and-data-exposure]
  }

  func copyPasswordWithExpiry(password: String) {
    UIPasteboard.general.setItems([["public.text": password]], options: [.localOnly: true, .expirationDate: Date(timeIntervalSinceNow: 60)]) // GOOD (local-only and expiring)
  }

  func copyDecrypted(item: String) {
    let plain = decryptString(item)
    UIPasteboard.general.string = plain // $ Alert[swift/credential-and-data-exposure]
  }
}

// --- session token ---

struct SignInModel {
  var email: String
  var password: String
}

class NetworkCalls {
  var sessionToken: String = ""

  func auth(_ info: SignInModel, handler: (String) -> Void) {
    let userData = "\(info.email):\(info.password)"
    let token = Crypto.encrypt(userData) // $ Alert[swift/credential-and-data-exposure]
    handler(token)
  }

  func auth2(_ info: SignInModel) {
    self.sessionToken = Crypto.encrypt(info.password) // $ Alert[swift/credential-and-data-exposure]
  }

  func storeBlob(_ info: SignInModel) -> String {
    let encryptedBlob = Crypto.encrypt(info.password) // GOOD (not used as a session token)
    return encryptedBlob
  }

  func authWithServerToken(_ info: SignInModel, serverResponse: String) {
    let token = Crypto.encrypt(serverResponse) // GOOD (not derived from credentials)
    self.sessionToken = token
  }
}

// --- app delegate ---

class AppDelegate : UIResponder, UIApplicationDelegate { // BAD (alert spans the class declaration and is matched on its last line)
  var window: UIWindow?

  func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [String : Any]?) -> Bool {
    return true
  }
} // $ Alert[swift/credential-and-data-exposure]

extension AppDelegate {
  func configureRootController() {
    self.window = UIWindow()
  }
}

class SafeAppDelegate : UIResponder, UIApplicationDelegate { // GOOD (obscures the window on backgrounding)
  var window: UIWindow?
  var privacyView: UIView?

  func applicationDidEnterBackground(_ application: UIApplication) {
    privacyView = UIView()
  }
}

class SafeAppDelegate2 : UIResponder, UIApplicationDelegate {
  var window: UIWindow?
}

extension SafeAppDelegate2 { // GOOD (obscures the window from an extension)
  func applicationWillResignActive(_ application: UIApplication) {
    window = nil
  }
}

class ResetPasswordViewController : UIViewController {
  weak var securityAnswerField: UITextField!
  weak var passwordField: UITextField!
  weak var nameField: UITextField!
}

// --- keychain missing ---

func savePassword(_ encodedPassword: Data) {
  var newItem = [String : Any]()
  newItem[kSecClass] = kSecClassGenericPassword
  newItem[kSecAttrAccount] = "user"
  newItem[kSecValueData] = encodedPassword
  let status = SecItemAdd(newItem, nil) // $ Alert[swift/credential-and-data-exposure]
}

// --- caching ---

class KeyFetcher {
  let demoEndpoint = "http://localhost:8081/webkit.php"

  func fetchKey() {
    guard let url = URL(string: demoEndpoint) else { return }
    var urlRequest = URLRequest(url: url)
    urlRequest.cachePolicy = .returnCacheDataElseLoad // $ Alert[swift/credential-and-data-exposure]
    urlRequest.httpBody = "token=key".data(using: 4)
  }

  func fetchKeyNoCache() {
    guard let url = URL(string: demoEndpoint) else { return }
    var urlRequest = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData) // GOOD (no caching)
    urlRequest.httpBody = "token=key".data(using: 4)
  }

  func fetchCredentials(password: String) {
    guard let url = URL(string: demoEndpoint) else { return }
    let urlRequest = URLRequest(url: url, cachePolicy: .returnCacheDataDontLoad) // $ Alert[swift/credential-and-data-exposure]
    let body = password.data(using: 4)
  }

  func fetchImages() {
    guard let url = URL(string: "http://localhost:8081/logo.png") else { return }
    let urlRequest = URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad) // GOOD (not sensitive)
  }
}

// --- memory ---

class MemoryManagementVC : UIViewController {
  weak var cardNoTextField: UITextField!
  var cardNumberString: String = ""
  var clearedCardNumber: String = ""
  var itemName: String = ""

  func payItemPressed() {
    self.cardNumberString = self.cardNoTextField.text ?? "" // $ Alert[swift/credential-and-data-exposure]
    self.itemName = self.cardNoTextField.text ?? "" // GOOD (not sensitive)
  }

  func payAndClear() {
    clearedCardNumber = cardNoTextField.text ?? "" // GOOD (cleared below)
  }

  func viewWillDisappear() {
    clearedCardNumber = ""
  }
}
