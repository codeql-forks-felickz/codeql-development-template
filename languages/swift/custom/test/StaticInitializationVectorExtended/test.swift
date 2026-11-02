// --- stubs ---

typealias CCCryptorStatus = Int32
typealias CCOperation = UInt32
typealias CCAlgorithm = UInt32
typealias CCOptions = UInt32
typealias CCMode = UInt32
typealias CCPadding = UInt32
typealias CCModeOptions = UInt32
typealias CCCryptorRef = OpaquePointer

let kCCSuccess = 0
let kCCEncrypt = 0
let kCCDecrypt = 1
let kCCAlgorithmAES = 0
let kCCAlgorithmAES128 = 0
let kCCAlgorithmRC4 = 4
let kCCOptionPKCS7Padding = 1
let kCCOptionECBMode = 2
let kCCModeECB = 1
let kCCModeCBC = 2
let kCCModeRC4 = 9
let ccPKCS7Padding = 1
let kCCKeySizeAES128 = 16
let kCCBlockSizeAES128 = 16

func CCCrypt(_ op: CCOperation, _ alg: CCAlgorithm, _ options: CCOptions, _ key: UnsafeRawPointer!, _ keyLength: Int, _ iv: UnsafeRawPointer!, _ dataIn: UnsafeRawPointer!, _ dataInLength: Int, _ dataOut: UnsafeMutableRawPointer!, _ dataOutAvailable: Int, _ dataOutMoved: UnsafeMutablePointer<Int>!) -> CCCryptorStatus { return 0 }

func CCCryptorCreate(_ op: CCOperation, _ alg: CCAlgorithm, _ options: CCOptions, _ key: UnsafeRawPointer!, _ keyLength: Int, _ iv: UnsafeRawPointer!, _ cryptorRef: UnsafeMutablePointer<CCCryptorRef?>!) -> CCCryptorStatus { return 0 }

func CCCryptorCreateWithMode(_ op: CCOperation, _ mode: CCMode, _ alg: CCAlgorithm, _ padding: CCPadding, _ iv: UnsafeRawPointer!, _ key: UnsafeRawPointer!, _ keyLength: Int, _ tweak: UnsafeRawPointer!, _ tweakLength: Int, _ numRounds: Int32, _ options: CCModeOptions, _ cryptorRef: UnsafeMutablePointer<CCCryptorRef?>!) -> CCCryptorStatus { return 0 }

func CCCryptorReset(_ cryptorRef: CCCryptorRef!, _ iv: UnsafeRawPointer!) -> CCCryptorStatus { return 0 }

struct Data {
	init(count: Int) { }
	init(_ elements: [UInt8]) { }

	var count: Int { get { return 0 } }

	// Like the Foundation methods, these stubs do not visibly call `body`.
	func withUnsafeBytes<ResultType, ContentType>(_ body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		fatalError()
	}

	mutating func withUnsafeMutableBytes<ResultType, ContentType>(_ body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		fatalError()
	}
}

struct CBC {
	init(iv: Array<UInt8>) { }
}

class RNCryptor { }

class RNEncryptor : RNCryptor {
	func encryptData(_ thePlaintext: Data?, with theSettings: Int, encryptionKey anEncryptionKey: Data?, hmacKey anHMACKey: Data?, iv anIV: Data?) throws -> Data { return Data(count: 0) }
}

func getRandomArray() -> [UInt8] {
	(0..<16).map({ _ in UInt8.random(in: 0...UInt8.max) })
}

// --- tests ---

// Reduced from iGoat-Swift `WebkitCacheExerciseVC.aesCBCDecrypt(data:keyData:)`.
func aesCBCDecrypt(data: Data, keyData: Data) -> Data? {
	let keyLength = keyData.count
	let clearLength = 500
	var clearData = Data(count: clearLength)
	var numBytesDecrypted = 0
	let options = CCOptions(kCCOptionPKCS7Padding)

	let cryptStatus = clearData.withUnsafeMutableBytes { cryptBytes in
		data.withUnsafeBytes { dataBytes in
			keyData.withUnsafeBytes { keyBytes in
				CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), options, keyBytes, keyLength, nil, dataBytes, data.count, cryptBytes, clearLength, &numBytesDecrypted) // $ Alert
			}
		}
	}

	if Int(cryptStatus) == kCCSuccess {
		return clearData
	}
	return nil
}

// Reduced from iGoat-Swift `Data.aes(operation:keyData:ivData:)`.
extension Data {
	func aes(operation: Int = kCCEncrypt, keyData: Data, ivData: Data = Data([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70])) -> Data {
		let dataLength = self.count
		let cryptLength = dataLength + kCCBlockSizeAES128
		var cryptData = Data(count: cryptLength)
		let keyLength = kCCKeySizeAES128
		let options = CCOptions(kCCOptionPKCS7Padding)
		var numBytesEncrypted = 0

		let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
			self.withUnsafeBytes { dataBytes in
				ivData.withUnsafeBytes { ivBytes in
					keyData.withUnsafeBytes { keyBytes in
						CCCrypt(CCOperation(operation), CCAlgorithm(kCCAlgorithmAES), options, keyBytes, keyLength, ivBytes, dataBytes, dataLength, cryptBytes, cryptLength, &numBytesEncrypted) // $ Alert
					}
				}
			}
		}

		if Int(cryptStatus) != kCCSuccess {
			return Data(count: 0)
		}
		return cryptData
	}

	// The default IV is never used, because every caller passes its own IV.
	func aesExplicitIvOnly(keyData: Data, ivData: Data = Data([0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70])) -> Data {
		var cryptData = Data(count: self.count + kCCBlockSizeAES128)
		var numBytesEncrypted = 0

		_ = cryptData.withUnsafeMutableBytes { cryptBytes in
			self.withUnsafeBytes { dataBytes in
				ivData.withUnsafeBytes { ivBytes in
					keyData.withUnsafeBytes { keyBytes in
						CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), keyBytes, kCCKeySizeAES128, ivBytes, dataBytes, self.count, cryptBytes, self.count + kCCBlockSizeAES128, &numBytesEncrypted) // GOOD: the IV always comes from the caller
					}
				}
			}
		}
		return cryptData
	}
}

func encryptWithDefaultIv(plain: Data, key: Data) -> Data {
	return plain.aes(keyData: key) // $ Source
}

func encryptWithRandomIv(plain: Data, key: Data) -> Data {
	let iv = Data(getRandomArray())
	_ = plain.aesExplicitIvOnly(keyData: key, ivData: iv) // GOOD: random IV
	return plain.aes(operation: kCCEncrypt, keyData: key, ivData: iv) // GOOD: random IV
}

func testCommonCrypto(key: [UInt8], dataIn: [UInt8], dataOut: UnsafeMutableRawPointer) {
	var moved = 0
	var cryptor: CCCryptorRef? = nil

	// static IVs
	let staticIv: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] // $ Source
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, staticIv, dataIn, dataIn.count, dataOut, 64, &moved) // $ Alert
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, "0123456789abcdef", dataIn, dataIn.count, dataOut, 64, &moved) // $ Alert
	_ = CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, staticIv, &cryptor) // $ Alert

	// nil (all-zero) IVs
	_ = CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, nil, &cryptor) // $ Alert
	_ = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCBC), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccPKCS7Padding), nil, key, key.count, nil, 0, 0, 0, &cryptor) // $ Alert
	_ = CCCryptorReset(cryptor, nil) // $ Alert

	// random IVs
	let randomIv = getRandomArray()
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, randomIv, dataIn, dataIn.count, dataOut, 64, &moved) // GOOD
	_ = CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding), key, key.count, randomIv, &cryptor) // GOOD
	_ = CCCryptorReset(cryptor, randomIv) // GOOD

	// ECB mode ignores the IV (ECB itself is a different weakness)
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding), key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // GOOD
	let ecbOptions = CCOptions(kCCOptionECBMode)
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), ecbOptions, key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // GOOD
	let wrappedEcbOptions = CCOptions(UInt32((kCCOptionECBMode)) | UInt32(kCCOptionPKCS7Padding))
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), wrappedEcbOptions, key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // GOOD
	let cbcOptions = CCOptions(kCCOptionPKCS7Padding & ~kCCOptionECBMode)
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), cbcOptions, key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // $ Alert
	let conditionalOptions = CCOptions(dataIn.count > 0 ? kCCOptionECBMode : kCCOptionPKCS7Padding)
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), conditionalOptions, key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // $ Alert
	_ = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeECB), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccPKCS7Padding), nil, key, key.count, nil, 0, 0, 0, &cryptor) // GOOD

	// the RC4 stream cipher ignores the IV (RC4 itself is a different weakness)
	_ = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmRC4), 0, key, key.count, nil, dataIn, dataIn.count, dataOut, 64, &moved) // GOOD
	_ = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeRC4), CCAlgorithm(kCCAlgorithmRC4), 0, nil, key, key.count, nil, 0, 0, 0, &cryptor) // GOOD
}

func testOtherLibraries(plain: Data, key: Data) {
	// RNCryptor generates a random IV when `nil` is passed
	_ = try? RNEncryptor().encryptData(plain, with: 0, encryptionKey: key, hmacKey: key, iv: nil) // GOOD

	// already reported by the standard `swift/static-initialization-vector` query
	_ = CBC(iv: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]) // GOOD (not duplicated)
}
