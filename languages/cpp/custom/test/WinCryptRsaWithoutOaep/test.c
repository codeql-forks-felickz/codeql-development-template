#include "../WinCryptStubs/wincrypt.h"

void rsa_encrypt_bad(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *payload, DWORD *payloadLen) {
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_RSA_SIGN, hHash, 0, &hKey);
  CryptEncrypt(hKey, 0, 1, 0, payload, payloadLen, 200); // $ Alert
}

void rsa_decrypt_bad(HCRYPTPROV hProv, BYTE *payload, DWORD *payloadLen) {
  HCRYPTKEY hKey;
  CryptGenKey(hProv, CALG_RSA_KEYX, 0, &hKey);
  CryptDecrypt(hKey, 0, 1, 0, payload, payloadLen); // $ Alert
}

void rsa_encrypt_good(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *payload, DWORD *payloadLen) {
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_RSA_SIGN, hHash, 0, &hKey);
  CryptEncrypt(hKey, 0, 1, CRYPT_OAEP, payload, payloadLen, 200);
}

void rsa_decrypt_good(HCRYPTPROV hProv, BYTE *payload, DWORD *payloadLen) {
  HCRYPTKEY hKey;
  CryptGenKey(hProv, CALG_RSA_KEYX, 0, &hKey);
  CryptDecrypt(hKey, 0, 1, CRYPT_OAEP, payload, payloadLen);
}

void aes_encrypt_good(HCRYPTPROV hProv, HCRYPTHASH hHash, BYTE *payload, DWORD *payloadLen) {
  HCRYPTKEY hKey;
  CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
  CryptEncrypt(hKey, 0, 1, 0, payload, payloadLen, 200);
}
