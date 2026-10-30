// --- stubs ---

import Foundation

class UIDevice {
  static var current: UIDevice = UIDevice()
  var identifierForVendor: UUID? { get { return nil } }
  var name: String { get { return "" } }
}

class ASIdentifierManager {
  static func shared() -> ASIdentifierManager { return ASIdentifierManager() }
  var advertisingIdentifier: UUID { get { return UUID() } }
}

class UITextField {
  var text: String?
}

// CryptoSwift
class AES {
  init(key: String, iv: String) throws {}
}

var SQLITE_OK: Int32 = 0

func sqlite3_exec(
  _ _: OpaquePointer?,
  _ sql: UnsafePointer<CChar>?,
  _ callback: (@convention(c) (UnsafeMutableRawPointer?, Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32)?,
  _ _: UnsafeMutableRawPointer?,
  _ errmsg: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 { return SQLITE_OK }

func randomKeyString() -> String { return "" }

// --- tests ---

// Reduced from the reported pattern: the SQLCipher database key is the device identifier.
func storeCredentials(db: OpaquePointer?) {
  let deviceID = UIDevice.current.identifierForVendor?.uuidString // $ Source
  if let aVendor = UIDevice.current.identifierForVendor {
    print("encryption key is \(aVendor)") // GOOD: not used as a key here
  }
  let encrptStmt = "PRAGMA key = '\(deviceID ?? "")'"
  _ = sqlite3_exec(db, encrptStmt, nil, nil, nil) // $ Alert

  let createStmt = "CREATE TABLE IF NOT EXISTS creds (id INTEGER PRIMARY KEY, username TEXT);"
  _ = sqlite3_exec(db, createStmt, nil, nil, nil) // GOOD: not a key
}

func rekeyWithConcatenation(db: OpaquePointer?) {
  let deviceID = UIDevice.current.identifierForVendor!.uuidString // $ Source
  _ = sqlite3_exec(db, "PRAGMA rekey = '" + deviceID + "'", nil, nil, nil) // $ Alert
}

func keyWithStringFormat(db: OpaquePointer?) {
  let deviceID = UIDevice.current.identifierForVendor!.uuidString // $ Source
  let statement = String(format: "PRAGMA key = '%@'", deviceID)
  _ = sqlite3_exec(db, statement, nil, nil, nil) // $ Alert
}

func keyWithInterpolatedUUID(db: OpaquePointer?) {
  if let vendorID = UIDevice.current.identifierForVendor { // $ Source
    _ = sqlite3_exec(db, "PRAGMA key = '\(vendorID)'", nil, nil, nil) // $ Alert
  }
}

func storeDeviceIdentifierInMixedStatement(db: OpaquePointer?) {
  let deviceID = UIDevice.current.identifierForVendor!.uuidString
  let randomKey = randomKeyString()
  let statement =
    "PRAGMA key = '" + randomKey + "'; INSERT INTO devices(id) VALUES ('" + deviceID + "');"
  _ = sqlite3_exec(db, statement, nil, nil, nil) // GOOD: the device identifier is only inserted
}

func cryptoSwiftKeyFromAdvertisingIdentifier() throws {
  let adID = ASIdentifierManager.shared().advertisingIdentifier.uuidString // $ Source
  _ = try AES(key: adID, iv: "0123456789abcdef") // $ Alert
}

func cryptoSwiftKeyFromVendorIdentifier() throws {
  let key = UIDevice.current.identifierForVendor?.uuidString ?? "" // $ Source
  _ = try AES(key: key, iv: "0123456789abcdef") // $ Alert
}

// --- safe counterparts ---

func storeDeviceIdentifierAsData(db: OpaquePointer?) {
  let deviceID = UIDevice.current.identifierForVendor?.uuidString ?? ""
  let insertStmt = "INSERT INTO devices (id) VALUES ('\(deviceID)')"
  _ = sqlite3_exec(db, insertStmt, nil, nil, nil) // GOOD: identifier is stored, not used as a key
}

func verifyItem(field: UITextField) -> Bool {
  let encryptionKeyStr = UIDevice.current.identifierForVendor?.uuidString
  return encryptionKeyStr == field.text // GOOD: comparison only
}

func keyFromRandomMaterial(db: OpaquePointer?) throws {
  let key = randomKeyString()
  _ = sqlite3_exec(db, "PRAGMA key = '\(key)'", nil, nil, nil) // GOOD: key is not a device identifier
  _ = try AES(key: key, iv: "0123456789abcdef") // GOOD
}
