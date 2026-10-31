// --- stubs ---

class NSObject { }

struct _NSRange { }

typealias NSRange = _NSRange

struct URL {
	init?(string: String) {}
}

extension String {
	init(contentsOf: URL) throws {
		self.init("")
	}
}

class WKNavigation : NSObject { }

class UIResponder : NSObject { }

class UIView : UIResponder { }

class UIControl : UIView { }

class UIViewController : UIResponder { }

class UITextField : UIControl {
	var text: String? {
		get { nil }
		set { }
	}

	var placeholder: String? {
		get { nil }
		set { }
	}
}

protocol UITextFieldDelegate {
	func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool
}

class UIWebView : UIView {
	func loadHTMLString(_ string: String, baseURL: URL?) {} // deprecated
}

class WKWebView : UIView {
	func loadHTMLString(_ string: String, baseURL: URL?) -> WKNavigation? {
		return WKNavigation()
	}
}

// --- tests ---

// Reduced from the iGoat-Swift XSS exercise.
class CrossSiteScriptingExerciseVC : UIViewController {
	var webview: UIWebView!
	var textField: UITextField!

	func loadItemPressed() {
		let webText = "Welcome to XSS Exercise !!! \n Here is UIWebView ! \(textField.text ?? "")"
		webview.loadHTMLString(webText, baseURL: nil) // $ unsafeWebViewFetchLocalInput
	}
}

class WKWebViewExerciseVC : UIViewController {
	var webview: WKWebView!
	var textField: UITextField!

	func concatenated() {
		let html = "<html><body>" + (textField.text ?? "") + "</body></html>"
		_ = webview.loadHTMLString(html, baseURL: nil) // $ unsafeWebViewFetchLocalInput
	}

	func taintedBaseUrl() {
		let text = textField.text ?? ""
		_ = webview.loadHTMLString("<p>\(text)</p>", baseURL: URL(string: text)) // $ unsafeWebViewFetchLocalInput
	}

	func safeBaseUrl() {
		let text = textField.text ?? ""
		_ = webview.loadHTMLString("<p>\(text)</p>", baseURL: URL(string: "about:blank")) // GOOD: a safe baseURL is specified
	}

	func constantHtml() {
		_ = webview.loadHTMLString("<p>Hello</p>", baseURL: nil) // GOOD: the HTML is constant
	}

	func placeholderIsNotUserInput() {
		let html = "<p>\(textField.placeholder ?? "")</p>"
		_ = webview.loadHTMLString(html, baseURL: nil) // GOOD: the placeholder is set by the app, not typed by the user
	}

	func remoteInputIsCoveredByStandardQuery() {
		let html = try! String(contentsOf: URL(string: "http://example.com/")!)
		_ = webview.loadHTMLString(html, baseURL: nil) // GOOD: remote input is reported by swift/unsafe-webview-fetch instead
	}
}

class MyTextFieldDelegate : UITextFieldDelegate {
	var webview: UIWebView!

	func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
		webview.loadHTMLString("<p>\(string)</p>", baseURL: nil) // $ unsafeWebViewFetchLocalInput
		return true
	}
}
