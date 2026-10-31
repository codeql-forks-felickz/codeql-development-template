// CWE-319: an encryption key downloaded from an `http://` endpoint and used
// for encryption with CommonCrypto.

enum KeyServerConstants {
  enum EndPoints {
    static let cryptoKey = "http://localhost:8081/cryptoKey.php"
    static let secureCryptoKey = "https://localhost:8443/cryptoKey.php"
  }
}

class KeyStorageServerSideViewController: UIViewController {
  var encryptionKey = ""

  func fetchKeyFromServer() {
    guard let url = URL(string: KeyServerConstants.EndPoints.cryptoKey) else { return }
    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = "POST"
    let task = URLSession.shared.dataTask(
      with: urlRequest,
      completionHandler: { data, response, error in
        if let data = data {
          let message = String(data: data, encoding: .utf8)
          self.encrypt(usingResponseString: message)
        }
      })
    task.resume()
  }

  func encrypt(usingResponseString responseString: String?) {
    guard let key = responseString else { return }
    encryptionKey = key
    let message = "SecretPass".data(using: .utf8)!
    _ = message.aes(keyData: encryptionKey.data(using: .utf8)!)
  }

  func fetchKeySecurely() {
    guard let url = URL(string: KeyServerConstants.EndPoints.secureCryptoKey) else { return }
    let task = URLSession.shared.dataTask(
      with: URLRequest(url: url),
      completionHandler: { data, response, error in
        if let data = data {
          _ = "SecretPass".data(using: .utf8)!.aesWithTrustedKey(keyData: data)
        }
      })
    task.resume()
  }
}

extension Data {
  func aes(keyData: Data) -> Data {
    var moved = 0
    _ = keyData.withUnsafeBytes { keyBytes in
      CCCrypt(
        CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, 16, nil, nil, 0, nil, 0, &moved) // $ keyFromCleartextHttp
    }
    return self
  }

  func aesWithTrustedKey(keyData: Data) -> Data {
    var moved = 0
    _ = keyData.withUnsafeBytes { keyBytes in
      // GOOD: the key is received over HTTPS
      CCCrypt(
        CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes.baseAddress, 16, nil, nil, 0, nil, 0, &moved)
    }
    return self
  }
}
