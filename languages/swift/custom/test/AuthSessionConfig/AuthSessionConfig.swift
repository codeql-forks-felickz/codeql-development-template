// --- stubs ---

import Foundation

class UIView {}

class UIViewController {}

protocol UIWebViewDelegate: AnyObject {}

class UIWebView: UIView {
  weak var delegate: UIWebViewDelegate?
  func loadRequest(_ request: URLRequest) {}
  func loadHTMLString(_ string: String, baseURL: URL?) {}
}

class WKNavigation {}

class WKNavigationAction {
  var request: URLRequest { get { return URLRequest(url: URL(string: "about:blank")!) } }
}

enum WKNavigationActionPolicy {
  case cancel
  case allow
}

protocol WKNavigationDelegate: AnyObject {}

class WKWebView: UIView {
  weak var navigationDelegate: WKNavigationDelegate?
  func load(_ request: URLRequest) -> WKNavigation? { return nil }
  func loadHTMLString(_ string: String, baseURL: URL?) -> WKNavigation? { return nil }
}

// --- tests ---

// Reduced from the reported pattern: tutorials are loaded into a `UIWebView`
// that has no delegate, so links in the remote content can navigate anywhere.
class TutorialViewController: UIViewController {
  var wv: UIWebView!
  var tURL: String = ""
  var curTut: Int = 1

  func viewDidLoad() {
    self.wv.loadRequest(URLRequest(url: URL(string: "\(self.tURL)/m\(self.curTut)")!)) // $ Alert
  }

  func nextTutorial() {
    self.curTut = self.curTut + 1
    self.wv.loadRequest(URLRequest(url: URL(string: "\(self.tURL)/m\(self.curTut)")!)) // $ Alert
  }
}

class UnrestrictedWKViewController: UIViewController {
  var webView: WKWebView?

  func show(url: URL) {
    _ = webView?.load(URLRequest(url: url)) // $ Alert
  }
}

func showLocalWebView(url: URL) -> WKWebView {
  let webView = WKWebView()
  _ = webView.load(URLRequest(url: url)) // $ Alert
  return webView
}

class NavigationPolicy: WKNavigationDelegate {
  func webView(
    _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
    decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
  ) {
    decisionHandler(navigationAction.request.url?.host == "example.com" ? .allow : .cancel)
  }
}

// Clearing the delegate does not restrict navigation.
class ClearedDelegateController: UIViewController {
  var webView = WKWebView()

  func show(url: URL) {
    webView.navigationDelegate = nil
    _ = webView.load(URLRequest(url: url)) // $ Alert
  }
}

// Only the first web view gets a navigation delegate.
class TwoWebViewsController: UIViewController {
  var restricted = WKWebView()
  var unrestricted = WKWebView()
  let policy = NavigationPolicy()

  func setUp(url: URL) {
    restricted.navigationDelegate = policy
    _ = restricted.load(URLRequest(url: url)) // GOOD: navigation delegate assigned
    _ = unrestricted.load(URLRequest(url: url)) // $ Alert
  }
}

// --- safe counterparts ---

class RestrictedTutorialViewController: UIViewController, UIWebViewDelegate {
  var wv: UIWebView!
  var tURL: String = ""

  func viewDidLoad() {
    self.wv.delegate = self
    self.wv.loadRequest(URLRequest(url: URL(string: "\(self.tURL)/m1")!)) // GOOD: delegate restricts navigation
  }

  func webView(
    _ webView: UIWebView, shouldStartLoadWith request: URLRequest, navigationType: Int
  ) -> Bool {
    return request.url?.host == URL(string: tURL)?.host
  }
}

class RestrictedWKViewController: UIViewController, WKNavigationDelegate {
  var webView: WKWebView?

  func setUp() {
    webView?.navigationDelegate = self
  }

  func show(url: URL) {
    _ = webView?.load(URLRequest(url: url)) // GOOD: navigation delegate assigned in setUp()
  }

  func webView(
    _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
    decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
  ) {
    decisionHandler(navigationAction.request.url?.host == "example.com" ? .allow : .cancel)
  }
}

// The delegate is connected in Interface Builder, but this type implements the
// navigation policy callback.
class StoryboardDelegateViewController: UIViewController, UIWebViewDelegate {
  var wv: UIWebView!

  func show(url: URL) {
    wv.loadRequest(URLRequest(url: url)) // GOOD: type implements the navigation policy callback
  }

  func webView(
    _ webView: UIWebView, shouldStartLoadWith request: URLRequest, navigationType: Int
  ) -> Bool {
    return request.url?.host == "example.com"
  }
}

func showRestrictedLocalWebView(url: URL, policy: NavigationPolicy) -> WKWebView {
  let webView = WKWebView()
  webView.navigationDelegate = policy
  _ = webView.load(URLRequest(url: url)) // GOOD: navigation delegate assigned
  return webView
}
