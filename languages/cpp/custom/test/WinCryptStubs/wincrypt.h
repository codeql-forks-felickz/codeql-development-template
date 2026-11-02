/* Minimal stand-in for the Windows CryptoAPI header (wincrypt.h), using the same values. */
#ifndef WINCRYPT_STUB_H
#define WINCRYPT_STUB_H

typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned int ALG_ID;
typedef unsigned long ULONG_PTR;
typedef ULONG_PTR HCRYPTPROV;
typedef ULONG_PTR HCRYPTKEY;
typedef ULONG_PTR HCRYPTHASH;

#define ALG_CLASS_SIGNATURE (1 << 13)
#define ALG_CLASS_DATA_ENCRYPT (3 << 13)
#define ALG_CLASS_HASH (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE (5 << 13)
#define ALG_TYPE_ANY (0)
#define ALG_TYPE_RSA (2 << 9)
#define ALG_TYPE_BLOCK (3 << 9)
#define ALG_TYPE_STREAM (4 << 9)
#define ALG_SID_MD5 3
#define ALG_SID_SHA1 4
#define ALG_SID_SHA_256 12
#define ALG_SID_DES 1
#define ALG_SID_3DES 3
#define ALG_SID_RC4 1
#define ALG_SID_AES_256 16
#define ALG_SID_RSA_ANY 0
#define CALG_MD5 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
#define CALG_SHA1 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#define CALG_DES (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES)
#define CALG_3DES (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES)
#define CALG_RC4 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4)
#define CALG_AES_256 (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256)
#define CALG_RSA_SIGN (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
#define CALG_RSA_KEYX (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
#define CRYPT_OAEP 0x00000040

BOOL CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
BOOL CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);
BOOL CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);
BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

#endif
