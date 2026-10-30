// --- stubs (Foundation, CommonCrypto, Core Data, UIKit and Alamofire) ---

class NSObject {}

struct Data {
  struct Base64EncodingOptions: OptionSet {
    let rawValue: UInt
  }

  init<S: Sequence>(_ elements: S) where S.Element == UInt8 {}

  var count: Int { return 0 }

  func base64EncodedString(options: Data.Base64EncodingOptions = []) -> String { return "" }

  func withUnsafeBytes<ResultType>(_ body: (UnsafeRawBufferPointer) throws -> ResultType) rethrows
    -> ResultType
  {
    return try body(UnsafeRawBufferPointer(start: nil, count: 0))
  }
}

extension String {
  struct Encoding {
    static let utf8 = Encoding()
  }
}

extension StringProtocol {
  func data(using encoding: String.Encoding, allowLossyConversion: Bool = false) -> Data? {
    return Data(self.utf8)
  }
}

typealias CCOperation = UInt32
typealias CCAlgorithm = UInt32
typealias CCOptions = UInt32
typealias CCCryptorStatus = Int32

let kCCEncrypt = 0
let kCCAlgorithmAES = 0
let kCCOptionPKCS7Padding = 1

func CCCrypt(
  _ op: CCOperation, _ alg: CCAlgorithm, _ options: CCOptions, _ key: UnsafeRawPointer!,
  _ keyLength: Int, _ iv: UnsafeRawPointer!, _ dataIn: UnsafeRawPointer!, _ dataInLength: Int,
  _ dataOut: UnsafeMutableRawPointer!, _ dataOutAvailable: Int,
  _ dataOutMoved: UnsafeMutablePointer<Int>!
) -> CCCryptorStatus {
  return 0
}

class NSManagedObjectContext {}

class NSManagedObject: NSObject {}

class NSEntityDescription: NSObject {
  class func insertNewObject(forEntityName entityName: String, into context: NSManagedObjectContext)
    -> NSManagedObject
  {
    return NSManagedObject()
  }
}

struct URL {
  init?(string: String) {}
}

struct URLQueryItem {
  var name: String
  var value: String?
}

struct URLComponents {
  init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}

  var queryItems: [URLQueryItem]?
}

struct URLRequest {
  init(url: URL) {}

  var httpMethod: String?
  var httpBody: Data?

  mutating func setValue(_ value: String?, forHTTPHeaderField field: String) {}
}

class UIApplication {
  struct LaunchOptionsKey: Hashable {
    static let url = LaunchOptionsKey()
  }
}

protocol UIApplicationDelegate {
  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool
}

class UIViewController {}

class UITextField {
  var text: String?
}

class URLResponse {}

class URLSessionDataTask {
  func resume() {}
}

class URLSession {
  static let shared = URLSession()

  func dataTask(
    with request: URLRequest, completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
  ) -> URLSessionDataTask {
    return URLSessionDataTask()
  }
}

extension String {
  init?(data: Data, encoding: String.Encoding) { return nil }
}

class JSONSerialization {
  struct WritingOptions: OptionSet {
    let rawValue: UInt
    static let prettyPrinted = WritingOptions(rawValue: 1)
  }

  class func data(withJSONObject obj: Any, options opt: WritingOptions = []) throws -> Data {
    return Data([UInt8]())
  }
}

class RLMObject: NSObject {}

class RLMRealm {
  class func `default`() -> RLMRealm { return RLMRealm() }

  func add(_ object: RLMObject) {}
}

enum HTTPMethod {
  case get
  case post
}

class DataRequest {}

class Session {
  static let `default` = Session()

  func request<Parameters: Encodable>(
    _ convertible: String, method: HTTPMethod = .get, parameters: Parameters? = nil
  ) -> DataRequest {
    return DataRequest()
  }
}

let AF = Session.default
