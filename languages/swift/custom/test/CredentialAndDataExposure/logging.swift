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
