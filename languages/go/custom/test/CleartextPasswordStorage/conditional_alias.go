package main

import "database/sql"

func conditionalAliasHash(db *sql.DB, acct, other *Account, value string, condition bool) {
	target := acct
	if condition {
		target = other
	}
	target.Password = Encrypt(value)
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

// An ambiguous receiver can still overwrite this account's protected value.
func conditionalAliasPlaintextOverwrite(db *sql.DB, acct, other *Account, value string, condition bool) {
	acct.Password = Encrypt(value)
	target := acct
	if condition {
		target = other
	}
	target.Password = value
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

// Copying a struct does not create an alias to the original account's storage.
func copiedValueReceiver(db *sql.DB, acct Account, value string) {
	target := acct
	target.Password = Encrypt(value)
	db.Exec("INSERT INTO users VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

// A plaintext overwrite of a struct copy does not affect the hashed original.
func copiedValuePlaintextOverwrite(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	copy := acct
	copy.Password = value
	db.Exec("INSERT INTO users VALUES (?)", acct.Password)
}
