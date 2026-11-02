// --- stubs ---

typealias OSStatus = Int32
typealias CFDictionary = [String : Any]

let kSecClass: String = "class"
let kSecClassGenericPassword: String = "genp"
let kSecValueData: String = "v_Data"
let kSecAttrAccessible: String = "pdmn"
let kSecAttrAccessibleWhenUnlockedThisDeviceOnly: String = "aku"
let kSecAttrAccessibleAlways: String = "dk"

func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<AnyObject?>?) -> OSStatus { return 0 }

// --- tests ---

func savePasswordSafely(_ encodedPassword: String) {
  let item: [String : Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecValueData: encodedPassword,
    kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  ]
  let status = SecItemAdd(item, nil) // GOOD (restrictive accessibility set)
}

func savePasswordAlways(_ encodedPassword: String) {
  let item: [String : Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecValueData: encodedPassword,
    kSecAttrAccessible: kSecAttrAccessibleAlways // $ Alert[swift/credential-and-data-exposure]
  ]
  let status = SecItemAdd(item, nil)
}
