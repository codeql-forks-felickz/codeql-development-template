package main

import (
	"database/sql"

	"golang.org/x/crypto/bcrypt"
)

// Neither the input nor intermediate has a hash-like name: protection must
// originate at the bcrypt call, even after conversion and renaming.
func renamedBcryptPassword(db *sql.DB, value string) {
	encoded, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	password := string(encoded)
	db.Exec("INSERT INTO users VALUES (?)", password)
}

func renamedUnprotectedPassword(db *sql.DB, value string) {
	password := string([]byte(value))                 // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users VALUES (?)", password) // $ Alert[go/cleartext-password-storage-database]
}
