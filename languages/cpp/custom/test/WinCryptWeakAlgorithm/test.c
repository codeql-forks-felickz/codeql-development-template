#include "../WinCryptStubs/wincrypt.h"

void des_bad(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *data, DWORD *len) {
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_DES, hHash, 0, &hKey); // $ Alert
  CryptDecrypt(hKey, 0, 1, 0, data, len);
}

void rc4_bad(HCRYPTPROV hProv) {
  HCRYPTKEY hKey;
  CryptGenKey(hProv, CALG_RC4, 0, &hKey); // $ Alert
}

void triple_des_via_variable_bad(HCRYPTPROV hProv) {
  HCRYPTKEY hKey;
  ALG_ID alg = CALG_3DES;
  CryptGenKey(hProv, alg, 0, &hKey); // $ Alert
}

void md5_bad(HCRYPTPROV hProv, BYTE *password, DWORD passwordLen) {
  HCRYPTHASH hHash;
  CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash); // $ Alert
  CryptHashData(hHash, password, passwordLen, 0);
}

void sha1_bad(HCRYPTPROV hProv) {
  HCRYPTHASH hHash;
  CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash); // $ Alert
}

void aes_good(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *data, DWORD *len) {
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
  CryptDecrypt(hKey, 0, 1, 0, data, len);
}

void sha256_good(HCRYPTPROV hProv, BYTE *password, DWORD passwordLen) {
  HCRYPTHASH hHash;
  CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
  CryptHashData(hHash, password, passwordLen, 0);
}
