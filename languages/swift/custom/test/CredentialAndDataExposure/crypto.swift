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
  return ret
}

// GOOD: not presented as encryption
func encodeForTransport(_ value: String) -> String {
  return value.data(using: .utf8)!.base64EncodedString()
}
