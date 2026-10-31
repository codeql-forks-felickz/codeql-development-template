// CWE-532: payment card number, CVV and PIN from text fields written to the
// system log with `NSLog`.

func NSLog(_ format: String, _ args: CVarArg...) {}

class DeviceLogsViewController: UIViewController {
  var ccNoTextField = UITextField()
  var cvvTextField = UITextField()
  var pinTextField = UITextField()
  var nameTextField = UITextField()
  var pinnedTextField = UITextField()

  func submitItemPressed() {
    NSLog("ccNo: %@", ccNoTextField.text ?? "") // $ cleartextLogging
    NSLog("cvvNo: %@", cvvTextField.text ?? "") // $ cleartextLogging
    NSLog("pinNo: %@", pinTextField.text ?? "") // $ cleartextLogging
    // GOOD: not sensitive
    NSLog("name: %@", nameTextField.text ?? "")
    NSLog("pinned: %@", pinnedTextField.text ?? "")
  }
}

func decryptString(_ toDecrypt: String) -> String {
  // GOOD: the ciphertext is not sensitive plaintext
  NSLog("Decrypting \(toDecrypt)")
  let plaintext = String(data: Data([UInt8]()), encoding: .utf8)!
  NSLog("Decrypted value: \(plaintext)") // $ cleartextLogging
  return plaintext
}

func logCredentials(username: String, password: String, displayName: String) {
  NSLog("Login \(username):\(password)") // $ cleartextLogging
  // GOOD: a non-sensitive display name
  NSLog("Display name: \(displayName)")
}
