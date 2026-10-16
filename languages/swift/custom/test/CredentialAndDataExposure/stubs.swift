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
