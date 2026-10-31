// CWE-321 / CWE-329: hard-coded AES key and IV passed to CommonCrypto through
// global constants, a static property initializer and stored properties.

fileprivate let aesKey = "gEKC8qte1FvR3oJV"
fileprivate let aesIv = "MFQOKFtxfibUuDWo"

class Crypto {
  private static let aesInstance = AESCrypto(key: aesKey, iv: aesIv)

  static func encrypt(_ string: String) -> String {
    // GOOD (base64AsEncryption): the value is encrypted before it is encoded
    return aesInstance.encrypt(string: string).base64EncodedString()
  }
}

fileprivate class AESCrypto {
  private let key: Data
  private let iv: Data

  init(key: String, iv: String) {
    guard let keyData = key.data(using: .utf8) else {
      preconditionFailure("Error: Failed to set a key")
    }
    guard let ivData = iv.data(using: .utf8) else {
      preconditionFailure("Error: Failed to set an initial vector")
    }
    self.key = keyData
    self.iv = ivData
  }

  func encrypt(string: String) -> Data {
    let data = string.data(using: .utf8)!
    return crypt(data: data, option: CCOperation(kCCEncrypt))
  }

  func crypt(data: Data, option: CCOperation) -> Data {
    var bytesLength = 0
    _ = data.withUnsafeBytes { dataBytes in
      iv.withUnsafeBytes { ivBytes in
        key.withUnsafeBytes { keyBytes in
          CCCrypt(option, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, key.count, ivBytes.baseAddress, dataBytes.baseAddress, data.count, nil, 0, &bytesLength) // $ hardcodedKey staticIv
        }
      }
    }
    return data
  }
}

// GOOD: the key and IV are supplied by the caller (for example from the Keychain)
func cryptWithProvidedKey(key: Data, iv: Data, data: Data) {
  var bytesLength = 0
  _ = data.withUnsafeBytes { dataBytes in
    iv.withUnsafeBytes { ivBytes in
      key.withUnsafeBytes { keyBytes in
        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, key.count, ivBytes.baseAddress, dataBytes.baseAddress, data.count, nil, 0, &bytesLength)
      }
    }
  }
}

// CWE-311: Base64 encoding presented as encryption.

func encryptString(_ toEncrypt: String) -> String {
  let plainText = toEncrypt.data(using: .utf8)!
  let ret = plainText.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0)) // $ base64AsEncryption
  NSLog("Encrypting \(toEncrypt)") // $ cleartextLogging
  return ret
}

// Base64 helper; a caller that claims to encrypt should be reported.
func encodeForTransport(_ value: String) -> String {
  return value.data(using: .utf8)!.base64EncodedString() // $ base64AsEncryption
}

func encryptAndEncode(_ value: String) -> String {
  return encodeForTransport(value)
}

// GOOD: encoding without an encryption-named caller
func encodeForStorage(_ value: String) -> String {
  return value.data(using: .utf8)!.base64EncodedString()
}

private let constantArrayByte: UInt8 = UInt8(0x02)
private let hardcodedArrayKey: [UInt8] = [UInt8(0x01), constantArrayByte]
private let dynamicArrayKey: [UInt8] = [UInt8(0x01), UInt8.random(in: 0...255)]

func encryptWithHardcodedArrayKey(data: Data) {
  _ = hardcodedArrayKey.withUnsafeBytes { keyBytes in
    data.withUnsafeBytes { dataBytes in
      CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, hardcodedArrayKey.count, nil, dataBytes.baseAddress, data.count, nil, 0, nil) // $ hardcodedKey
    }
  }
}

func encryptWithDynamicArrayKey(data: Data) {
  _ = dynamicArrayKey.withUnsafeBytes { keyBytes in
    data.withUnsafeBytes { dataBytes in
      CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, dynamicArrayKey.count, nil, dataBytes.baseAddress, data.count, nil, 0, nil)
    }
  }
}
