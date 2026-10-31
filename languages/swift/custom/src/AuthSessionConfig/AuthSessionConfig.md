# Web view without a navigation policy

An in-app web view (`UIWebView` or `WKWebView`) follows every link in the content it displays unless the app installs a navigation delegate that decides which URLs may be loaded. If an app loads remote content into a web view and never assigns a `delegate` (`UIWebView`) or `navigationDelegate` (`WKWebView`), links or redirects in that content can navigate the web view to arbitrary third-party sites. Those sites are then shown inside the app's own interface, can store cookies and cached data in the app's web storage, and can ask the user for credentials in a context that looks like part of the application.

This query reports calls to `UIWebView.loadRequest(_:)` and `WKWebView.load(_:)` on a web view that is never given a non-`nil` navigation delegate, where the enclosing type also does not implement a navigation policy callback (`webView(_:shouldStartLoadWith:navigationType:)` or `webView(_:decidePolicyFor:decisionHandler:)`). The query does not check what the assigned delegate allows, and delegates that are connected only in Interface Builder to a different object are not visible to the query.

## Recommendation

Assign a navigation delegate to the web view and restrict navigation to the expected origin. Open any other links in the system browser (for example with `UIApplication.shared.open(_:)`) or block them. `UIWebView` is deprecated; prefer `WKWebView` with a `WKNavigationDelegate`.

## Example

The following example loads tutorial pages into a `UIWebView` with no delegate, so links in the tutorial content can navigate the web view anywhere:

```swift
class TutorialViewController: UIViewController {
  @IBOutlet weak var wv: UIWebView!

  override func viewDidLoad() {
    super.viewDidLoad()
    wv.loadRequest(URLRequest(url: tutorialURL)) // BAD: no navigation policy
  }
}
```

The following example uses a `WKWebView` whose navigation delegate only allows pages from the tutorial host and opens other links in the system browser:

```swift
class TutorialViewController: UIViewController, WKNavigationDelegate {
  @IBOutlet weak var webView: WKWebView!

  override func viewDidLoad() {
    super.viewDidLoad()
    webView.navigationDelegate = self
    webView.load(URLRequest(url: tutorialURL)) // GOOD
  }

  func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
               decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    guard let url = navigationAction.request.url else { return decisionHandler(.cancel) }
    if url.host == tutorialURL.host {
      decisionHandler(.allow)
    } else {
      UIApplication.shared.open(url)
      decisionHandler(.cancel)
    }
  }
}
```

## References

- MITRE: [CWE-939: Improper Authorization in Handler for Custom URL Scheme](https://cwe.mitre.org/data/definitions/939.html).
- Apple Developer Documentation: [WKNavigationDelegate](https://developer.apple.com/documentation/webkit/wknavigationdelegate).
- Apple Developer Documentation: [UIWebViewDelegate](https://developer.apple.com/documentation/uikit/uiwebviewdelegate).
