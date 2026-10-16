// CWE-200: a deep link selects the URL of a request that carries the user's
// authorization token.

class WebViewController: UIViewController {
  var url: URL!
  var token: String? = nil

  func set(url: URL) {
    self.url = url
  }

  var request: URLRequest {
    var request = URLRequest(url: url) // $ headersToUntrustedUrl
    if let token = token {
      request.setValue(token, forHTTPHeaderField: "Authorization")
    }
    return request
  }
}

class PlainWebViewController: UIViewController {
  var url: URL!

  func set(url: URL) {
    self.url = url
  }

  var request: URLRequest {
    // GOOD: no headers are attached to the request
    return URLRequest(url: url)
  }
}

class MainViewController: UIViewController {
  private var deeplink: URL?

  func set(deeplink: URL?) {
    self.deeplink = deeplink
  }

  func viewDidAppear() {
    if let deeplink = deeplink {
      handleDeeplink(deeplink)
    }
  }

  private func handleDeeplink(_ url: URL) {
    if let urlParam = getQueryParameter(url, "url"), let target = URL(string: urlParam) {
      let webVc = WebViewController()
      webVc.set(url: target)
      let plainVc = PlainWebViewController()
      plainVc.set(url: target)
    }
  }

  func getQueryParameter(_ url: URL, _ name: String) -> String? {
    if let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
      let params = components.queryItems
    {
      return params.first(where: { $0.name == name })?.value
    }
    return nil
  }
}

class AppDelegate: UIApplicationDelegate {
  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    let mainViewController = MainViewController()
    let deeplink = launchOptions?[.url] as? URL
    mainViewController.set(deeplink: deeplink)
    return true
  }
}

// GOOD: the URL is a trusted constant
func apiRequest(token: String) -> URLRequest {
  var request = URLRequest(url: URL(string: "https://api.example.com/")!)
  request.setValue(token, forHTTPHeaderField: "Authorization")
  return request
}
