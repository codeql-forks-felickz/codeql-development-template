# Unvalidated custom URL scheme parameter

Any app or web page can open an iOS app through a custom URL scheme (for example `myapp://send?to=...&message=...`) and choose every part of that URL. The URL arrives in `UIApplicationDelegate.application(_:open:options:)` or `UISceneDelegate.scene(_:openURLContexts:)`. If the app uses the query parameters of that URL to show messages, fill in an SMS or email composer, or open other URLs without validating them, an attacker can trigger those actions with values the attacker chooses (CWE-20, CWE-939).

## Recommendation

Treat every component of a deep link as untrusted input. Validate each parameter before you use it. For example, check it against an allow list or a strict format such as a phone number pattern, and reject the link if any parameter fails the check. Checking only the URL scheme or host is not enough, because any caller can use your scheme.

## Example

In this example, the app only checks the scheme and then shows a message that includes the `message` and `contactNumber` query parameters:

```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
  if url.scheme == "igoat", let queryInfo = url.parametersInfo {
    let mobileNo = queryInfo["contactNumber"] ?? ""
    let message = queryInfo["message"] ?? ""
    // BAD: attacker-controlled values are shown to the user as-is
    UIAlertController.showAlertWith(title: "iGoat", message: "Message \"\(message)\" sent to \(mobileNo)")
    return true
  }
  return false
}
```

In this version, each parameter is validated before it is used:

```swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
  guard url.scheme == "igoat", let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else {
    return false
  }
  let number = items.first?.value ?? ""
  let text = items.last?.value ?? ""
  // GOOD: each parameter is checked before use
  guard isValidPhoneNumber(number) else { return false }
  if !allowedMessages.contains(text) { return false }
  let composer = MFMessageComposeViewController()
  composer.recipients = [number]
  composer.body = text
  return true
}
```

## References

- Apple Developer Documentation: [Defining a custom URL scheme for your app](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app).
- OWASP MASTG: [Testing Deep Links](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/).
- Common Weakness Enumeration: [CWE-20](https://cwe.mitre.org/data/definitions/20.html).
- Common Weakness Enumeration: [CWE-939](https://cwe.mitre.org/data/definitions/939.html).
