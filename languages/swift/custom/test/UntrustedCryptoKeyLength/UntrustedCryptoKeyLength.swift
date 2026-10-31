import Foundation

let kCCKeySizeAES128 = 16

func CCCrypt(
    _ operation: Int,
    _ algorithm: Int,
    _ options: Int,
    _ key: Any?,
    _ keyLength: size_t,
    _ iv: Any?,
    _ input: Any?,
    _ inputLength: Int,
    _ output: Any?,
    _ outputLength: Int,
    _ outputMoved: Any?
) -> Int {
    return 0
}

func encryptData(keyData: Data, ivData: Data, input: Data, output: Data) {
    let keyLength = size_t(kCCKeySizeAES128)
    _ = keyData.withUnsafeBytes { keyBytes in
        CCCrypt(0, 0, 0, keyBytes, keyLength, ivData, input, input.count, output, output.count, nil) // $ Alert
    }
}

func encryptString(key: String, iv: String, input: Data, output: Data) {
    guard let keyData = key.data(using: .utf8) else { return }
    let keyLength = size_t(kCCKeySizeAES128)
    _ = CCCrypt(0, 0, 0, (keyData as NSData).bytes, keyLength, iv, input, input.count, output, output.count, nil) // $ Alert
}

func encryptCheckedKey(keyData: Data, ivData: Data, input: Data, output: Data) {
    guard keyData.count >= kCCKeySizeAES128 else { return }
    let keyLength = size_t(kCCKeySizeAES128)
    _ = keyData.withUnsafeBytes { keyBytes in
        CCCrypt(0, 0, 0, keyBytes, keyLength, ivData, input, input.count, output, output.count, nil)
    }
}

func encryptWithBufferLength(keyData: Data, ivData: Data, input: Data, output: Data) {
    _ = keyData.withUnsafeBytes { keyBytes in
        CCCrypt(0, 0, 0, keyBytes, size_t(keyData.count), ivData, input, input.count, output, output.count, nil)
    }
}

func encryptKnownKey(ivData: Data, input: Data, output: Data) {
    let keyData = Data(repeating: 0, count: kCCKeySizeAES128)
    let keyLength = size_t(kCCKeySizeAES128)
    _ = keyData.withUnsafeBytes { keyBytes in
        CCCrypt(0, 0, 0, keyBytes, keyLength, ivData, input, input.count, output, output.count, nil)
    }
}
