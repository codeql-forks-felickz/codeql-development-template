// --- stubs ---

class UIApplication {
    struct OpenURLOptionsKey : Hashable {
        static func == (lhs: OpenURLOptionsKey, rhs: OpenURLOptionsKey) -> Bool {
            return true;
        }

        func hash(into hasher: inout Hasher) {}
    }
}

struct URL {
    init?(string: String) {}

    var lastPathComponent: String { get { return "" } }
}

struct URLQueryItem {
    var name: String
    var value: String?
}

struct URLComponents {
    init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}

    var queryItems: [URLQueryItem]? { get { return nil } }
}

class NSURLComponents {
    init?(url: URL, resolvingAgainstBaseURL resolve: Bool) {}

    var queryItems: [URLQueryItem]? { get { return nil } }
}

struct Data : Sequence {
    init?(base64Encoded base64String: String) {}
    init(bytes: UnsafeRawPointer, count: Int) {}
    init<S: Sequence>(_ elements: S) where S.Element == UInt8 {}

    var count: Int { get { return 0 } }

    func makeIterator() -> IndexingIterator<[UInt8]> { return [UInt8]().makeIterator() }
}

protocol UIApplicationDelegate {
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any]) -> Bool
}

// --- tests ---

func getQueryParameter(_ url: URL, _ name: String) -> String? {
    if let components = NSURLComponents(url: url, resolvingAgainstBaseURL: true), let params = components.queryItems {
        if let value = params.first(where: { $0.name == name })?.value {
            return value
        }
    }
    return nil
}

class AppDelegate: UIApplicationDelegate {
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any]) -> Bool { // $ Source
        handleSave(url)
        handleOther(url)
        handleSafe(url)
        return true
    }

    // Reduced from the "save" deep-link route of a vulnerable iOS sample app.
    func handleSave(_ url: URL) {
        if url.lastPathComponent == "save",
           let dataParam = getQueryParameter(url, "data"),
           var data = Data(base64Encoded: dataParam) {
            if let offsetParam = getQueryParameter(url, "offset"), let offset = Int(offsetParam) {
                let arr = [UInt8](data)
                data = Data(bytes: &data + offset, count: arr.count - offset) // $ Alert
            }
            _ = data
        }
    }

    func handleOther(_ url: URL) {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        guard let raw = items.first?.value, let index = Int(raw) else { return }

        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { buffer.deallocate() }

        _ = buffer.advanced(by: index) // $ Alert
        _ = buffer[index] // $ Alert
        _ = buffer - index // $ Alert

        var cursor = UnsafeRawPointer(buffer)
        cursor += index // $ Alert
        _ = cursor

        let bytes = [UInt8](repeating: 0, count: 16)
        bytes.withUnsafeBufferPointer { ptr in
            _ = ptr.baseAddress! + index // $ Alert
        }
    }

    func handleSafe(_ url: URL) {
        let data = Data([1, 2, 3, 4])
        guard let offsetParam = getQueryParameter(url, "offset"), let offset = Int(offsetParam) else { return }

        // GOOD: offset is validated against the bounds of the buffer.
        if offset >= 0 && offset < data.count {
            var copy = data
            _ = Data(bytes: &copy + offset, count: data.count - offset)
        }

        // GOOD: guard statement rejects out-of-range offsets.
        guard offset >= 0, offset < data.count else { return }
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { buffer.deallocate() }
        _ = buffer.advanced(by: offset)

        // GOOD: range containment check.
        let other = UnsafeMutablePointer<UInt8>.allocate(capacity: 16)
        defer { other.deallocate() }
        if let raw = getQueryParameter(url, "index"), let index = Int(raw), (0..<16).contains(index) {
            _ = other[index]
        }

        // GOOD: constant offset, not attacker controlled.
        _ = other + 4
        _ = other.advanced(by: 8)
    }
}
