package main

import (
	"crypto/sha256"
	"database/sql"

	"gorm.io/gorm"
)

// Metadata words must be separate words, not substrings of admin/account.
func passwordNames(db *sql.DB,
	adminPassword string, // $ Source[go/cleartext-password-storage-database]
	accountPassword string, // $ Source[go/cleartext-password-storage-database]
	admin_password string, // $ Source[go/cleartext-password-storage-database]
	account_password string, // $ Source[go/cleartext-password-storage-database]
) {
	db.Exec("INSERT INTO users VALUES (?)", adminPassword)    // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", accountPassword)  // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", admin_password)   // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", account_password) // $ Alert[go/cleartext-password-storage-database]
}

func Decrypt(value string) string { return value }
func Open(value string) string    { return value }
func Unseal(value string) string  { return value }
func Encrypt(value string) string { return value }
func Seal(value string) string    { return value }

func decryptThenStore(db *sql.DB, password string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", Decrypt(password)) // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", Open(password))    // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", Unseal(password))  // $ Alert[go/cleartext-password-storage-database]
}

func protectionEntrypoints(db *gorm.DB, value string) {
	db.Create(&Account{Password: Encrypt(value)})
	db.Create(&Account{Password: Seal(value)})
	digest := sha256.Sum256([]byte(value))
	db.Create(&Account{Password: string(digest[:])})
}

func passwordMetadata(db *sql.DB, passwordHint, passwordPolicy, hashedPassword, password_hint, password_policy, hashed_password string) {
	db.Exec("INSERT INTO users VALUES (?)", passwordHint)
	db.Exec("INSERT INTO users VALUES (?)", passwordPolicy)
	db.Exec("INSERT INTO users VALUES (?)", hashedPassword)
	db.Exec("INSERT INTO users VALUES (?)", password_hint)
	db.Exec("INSERT INTO users VALUES (?)", password_policy)
	db.Exec("INSERT INTO users VALUES (?)", hashed_password)
}

func metadataIsNotProtection(db *gorm.DB, salt, hint, min string) {
	db.Create(&Account{Password: salt}) // $ Alert[go/cleartext-password-storage-database]
	db.Create(&Account{Password: hint}) // $ Alert[go/cleartext-password-storage-database]
	db.Create(&Account{Password: min})  // $ Alert[go/cleartext-password-storage-database]
}

func mixedProtection(db *gorm.DB, value string) {
	hash := sha256.Sum256([]byte(value))
	db.Create(&Account{Password: string(hash[:]) + ":" + value}) // $ Alert[go/cleartext-password-storage-database]
	db.Create(&Account{Password: value + ":" + string(hash[:])}) // $ Alert[go/cleartext-password-storage-database]
}

func protectedTransformations(db *gorm.DB, digest, kdfOutput string, value string) {
	hash := sha256.Sum256([]byte(value))
	db.Create(&Account{Password: "salt:" + string(hash[:])})
	db.Create(&Account{Password: digest + ":" + kdfOutput})
}

func renamedHash(db *sql.DB, value string) {
	digest := sha256.Sum256([]byte(value))
	password := string(digest[:])
	db.Exec("INSERT INTO users VALUES (?)", password)
}

func renamedPlaintext(db *sql.DB, value string) {
	password := value                                 // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", password) // $ Alert[go/cleartext-password-storage-database]
}

func readBeforeHash(db *sql.DB, acct Account, value string) {
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
	acct.Password = Encrypt(value)
}

func hashOtherReceiver(db *sql.DB, acct, other Account, value string) {
	other.Password = Encrypt(value)
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

func conditionalHash(db *sql.DB, acct Account, value string, condition bool) {
	if condition {
		acct.Password = Encrypt(value)
	}
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

func plaintextOverwrite(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	acct.Password = value
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

func precedingHash(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	db.Exec("INSERT INTO users VALUES (?)", acct.Password)
}

func precedingHashAlias(db *sql.DB, acct *Account, value string) {
	alias := acct
	alias.Password = Encrypt(value)
	db.Exec("INSERT INTO users VALUES (?)", acct.Password)
}

func commentedWrites(db *sql.DB, password string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec(" /* audit */ INSERT INTO users VALUES (?)", password)  // $ Alert[go/cleartext-password-storage-database]
	db.Exec(" \n-- audit\nUPDATE users SET password = ?", password) // $ Alert[go/cleartext-password-storage-database]
}

func commentedReads(db *sql.DB, password string) {
	db.Exec(" /* audit */ -- second comment\n SELECT id FROM users WHERE password = ?", password)
}

func updateLookupOnly(db *sql.DB, password string) {
	db.Exec("UPDATE users SET last_login = 'now' WHERE password = ?", password)
	db.Exec("UPDATE users SET password = '******' WHERE id = $1", password)
	db.Exec("UPDATE users SET password = $2 WHERE id = $1", password, "******")
}

func updateStoredParameters(db *sql.DB, password string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET password = ? WHERE id = ?", password, 1)                // $ Alert[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET password = $2 WHERE id = $1", 1, password)              // $ Alert[go/cleartext-password-storage-database]
	db.Exec(" /* audit */ UPDATE users SET password = $2 WHERE id = $1", 1, password) // $ Alert[go/cleartext-password-storage-database]
}

func updateQuotedPlaceholders(db *sql.DB, password string) {
	db.Exec("UPDATE users SET label = '? WHERE $1', last_login = ? WHERE password = ?", "now", password)
}

// Complex or unknown syntax retains the conservative all-arguments fallback.
func updateFallback(db *sql.DB, password string, query string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET last_login = (SELECT max(time) FROM logins WHERE password = ?)", password) // $ Alert[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET last_login = custom(?) WHERE id = 1", password)                            // $ Alert[go/cleartext-password-storage-database]
	db.Exec(query, password)                                                                             // $ Alert[go/cleartext-password-storage-database]
}

func mixedProtectionRenamed(db *gorm.DB, value string) {
	digest := sha256.Sum256([]byte(value))
	hashWithPlaintext := string(digest[:]) + ":" + value
	db.Create(&Account{Password: hashWithPlaintext}) // $ Alert[go/cleartext-password-storage-database]
}

func updateMultipleParameters(db *sql.DB, password string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET label = 'not ? or $1', username = ?, password = ? WHERE id = ?", "name", password, 1) // $ Alert[go/cleartext-password-storage-database]
	db.Exec("UPDATE users SET username = $2, password = $3 WHERE id = $1", 1, "name", password)                     // $ Alert[go/cleartext-password-storage-database]
}
