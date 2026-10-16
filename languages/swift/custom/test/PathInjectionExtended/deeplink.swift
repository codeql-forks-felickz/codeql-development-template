// --- stubs ---

struct URL {
    init?(string: String) {}

    var lastPathComponent: String { get { return "" } }

    func appendingPathComponent(_ pathComponent: String) -> URL { return self }
}

struct URLQueryItem {
    var name: String
    var value: String?
}

struct URLComponents {
    init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}

    var queryItems: [URLQueryItem]? { get { return nil } set {} }
}

class NSURLComponents {
    init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}

    var queryItems: [URLQueryItem]? { get { return nil } set {} }
}

class Data {
    struct Base64DecodingOptions : OptionSet { let rawValue: Int }
    struct WritingOptions : OptionSet { let rawValue: Int }

    init?(base64Encoded base64String: String, options: Data.Base64DecodingOptions = []) {}

    func write(to: URL, options: Data.WritingOptions = []) {}
}

class FileManager {
    enum SearchPathDirectory : UInt { case documentDirectory }
    struct SearchPathDomainMask : OptionSet {
        let rawValue: UInt
        static let userDomainMask = SearchPathDomainMask(rawValue: 1)
    }

    static let `default` = FileManager()

    func urls(for directory: FileManager.SearchPathDirectory, in domainMask: FileManager.SearchPathDomainMask) -> [URL] { return [] }
}

class UIApplication {
    struct OpenURLOptionsKey : Hashable {
        static func == (lhs: OpenURLOptionsKey, rhs: OpenURLOptionsKey) -> Bool {
            return true;
        }

        func hash(into hasher: inout Hasher) {}
    }
    struct LaunchOptionsKey: Hashable {
        init(rawValue: String) {}
        public static let url: UIApplication.LaunchOptionsKey = UIApplication.LaunchOptionsKey(rawValue: "")
        func hash(into hasher: inout Hasher) {}
    }
}

protocol UIApplicationDelegate {
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any]) -> Bool
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey : Any]?) -> Bool
}

class UIViewController {
    func viewDidAppear(_ animated: Bool) {}
}

// --- app helpers ---

extension FileManager {
    class func documentsUrlForFile(withName name: String) -> URL {
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return documents.appendingPathComponent(name)
    }
}

// --- tests ---

class AppDelegate: UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey : Any]?) -> Bool {
        let mainViewController = MainViewController()
        let deeplink = launchOptions?[.url] as? URL
        mainViewController.set(deeplink: deeplink)

        let safeViewController = SafeViewController()
        safeViewController.set(fileName: "report.bin")
        return true
    }

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any]) -> Bool {
        if let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let name = components.queryItems?.first(where: { $0.name == "name" })?.value,
           let data = Data(base64Encoded: "") {
            data.write(to: FileManager.documentsUrlForFile(withName: name)) // $ hasPathInjection
            data.write(to: FileManager.documentsUrlForFile(withName: "export.bin")) // safe: fixed file name
        }
        return true
    }
}

// The deep link is stored on the view controller and handled later in a UIKit
// lifecycle method (`viewDidAppear(_:)`) that is not called from app code.
class MainViewController: UIViewController {
    private var deeplink: URL?

    func set(deeplink: URL?) {
        self.deeplink = deeplink
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)

        if let deeplink = deeplink {
            handleDeeplink(deeplink)
        }
    }

    private func handleDeeplink(_ url: URL) {
        let route = url.lastPathComponent
        if route == "save",
           let dataParam = getQueryParameter(url, "data"),
           let data = Data(base64Encoded: dataParam),
           let name = getQueryParameter(url, "name") {
            data.write(to: FileManager.documentsUrlForFile(withName: name)) // $ hasPathInjection
            data.write(to: FileManager.documentsUrlForFile(withName: "export.bin")) // safe: fixed file name
        }
    }

    func getQueryParameter(_ url: URL, _ name: String) -> String? {
        if let components = NSURLComponents(url: url, resolvingAgainstBaseURL: true), let params = components.queryItems {
            if let value = params.first(where: { $0.name == name })?.value {
                return value
            }
        }
        return nil
    }
}

// The stored property is only ever assigned constant values.
class SafeViewController: UIViewController {
    private var fileName: String = "default.bin"

    func set(fileName: String) {
        self.fileName = fileName
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)

        if let data = Data(base64Encoded: "") {
            data.write(to: FileManager.documentsUrlForFile(withName: fileName)) // safe: constant file name
        }
    }
}
