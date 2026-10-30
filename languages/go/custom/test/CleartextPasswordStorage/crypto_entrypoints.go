package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"gorm.io/gorm"
)

// A neutral decrypted value must become a password source at the field write.
// No password-named parameter can independently supply the alert.
func decryptedValueStored(db *gorm.DB, key *rsa.PrivateKey, value []byte) {
	decoded, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, value, nil)
	if err != nil {
		return
	}
	db.Create(&Account{Password: string(decoded)}) // $ Alert[go/cleartext-password-storage-database]
}

// Marshaling is not encryption, despite the "sha" substring in "Marshal" and
// the crypto package path. Writing its result to Password is not suppressed.
func unrelatedCryptoValueStored(db *gorm.DB, key *rsa.PrivateKey) {
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	db.Create(&Account{Password: string(encoded)}) // $ Alert[go/cleartext-password-storage-database]
}
