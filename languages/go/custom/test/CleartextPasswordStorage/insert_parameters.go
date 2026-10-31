package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// The column supplies the password meaning, not an SSA name or format string.
func generatedInsert(db *sql.DB, n int) {
	db.Exec("INSERT INTO members (display_name, contact, password) VALUES (?, ?, ?)",
		fmt.Sprintf("Member %d", n), fmt.Sprintf("member%d@example.invalid", n),
		fmt.Sprintf("credential %d", n)) // $ Alert[go/cleartext-password-storage-database]
}

func neutralInsert(db *sql.DB, tx *sql.Tx, conn *sql.Conn, ctx context.Context, value string) {
	db.Exec("INSERT INTO members (password) VALUES (?)", value)                                     // $ Alert[go/cleartext-password-storage-database]
	tx.Exec("INSERT INTO members (password) VALUES (?)", value)                                     // $ Alert[go/cleartext-password-storage-database]
	db.ExecContext(ctx, "INSERT INTO members (password) VALUES (?)", value)                         // $ Alert[go/cleartext-password-storage-database]
	tx.ExecContext(ctx, "INSERT INTO members (password) VALUES (?)", value)                         // $ Alert[go/cleartext-password-storage-database]
	conn.ExecContext(ctx, " /* audit */ -- seed\n INSERT INTO members (passwd) VALUES (?);", value) // $ Alert[go/cleartext-password-storage-database]
}

func excludedInsert(db *sql.DB, value string, n int) {
	db.Exec("INSERT INTO members (display_name, contact) VALUES (?, ?)", value, value)
	db.Exec("INSERT INTO members (passwordHint, hashed_password) VALUES (?, ?)", value, value)
	sum := sha256.Sum256([]byte(value))
	db.Exec("INSERT INTO members (password) VALUES (?)", string(sum[:]))
	// A format literal mentioning password in another column is not a source.
	db.Exec("INSERT INTO members (display_name, password) VALUES (?, ?)", fmt.Sprintf("password %d", n), string(sum[:]))
	db.Exec("INSERT INTO members (password) VALUES (?)", "fixed credential")
	db.Exec("INSERT INTO members (password) VALUES (?)", n)
}

func numberedInsert(db *sql.DB, value string) {
	sum := sha256.Sum256([]byte(value))
	db.Exec("INSERT INTO members (display_name, password) VALUES ($2, $1)", value, string(sum[:])) // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (display_name, password) VALUES ($2, $1)", value, value)          // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (display_name, password) VALUES ($2, $1)", string(sum[:]), value)
}

func byteInsert(db *sql.DB, value []byte) {
	db.Exec("insert into members (password) values (?)", value) // $ Alert[go/cleartext-password-storage-database]
}

// Unsupported syntax must not invent a column-to-argument mapping.
func unsupportedInsert(db *sql.DB, stmt *sql.Stmt, value, query string) {
	db.Exec("INSERT INTO members (display_name, password) VALUES (?)", value)
	db.Exec("INSERT INTO members (password) VALUES (?, ?)", value, value)
	db.Exec("INSERT INTO members (password) VALUES ($2)", value)
	db.Exec("INSERT INTO members (password) VALUES (?)", value, value)
	db.Exec("INSERT INTO members (display_name, password) VALUES (?, ?)", value)
	db.Exec("INSERT INTO members (display_name, password) VALUES ($1, $1)", value, value)
	db.Exec("INSERT INTO members (display_name, password) VALUES ($1, $3)", value, value)
	db.Exec("INSERT INTO members (password) VALUES ($01)", value)
	db.Exec("INSERT INTO members (display_name, password) VALUES (?, $1)", value, value)
	db.Exec("INSERT INTO members (display_name, password) VALUES ('label', ?)", value)
	db.Exec("INSERT INTO members (password) VALUES (lower(?))", value)
	db.Exec("INSERT INTO members (password) VALUES (?),(?)", value, value)
	db.Exec("INSERT INTO members (password) VALUES (?) RETURNING id", value)
	db.Exec("INSERT INTO members (\"password\") VALUES (?)", value)
	db.Exec("INSERT INTO members (password) VALUES (?); SELECT 1", value)
	stmt.Exec("INSERT INTO members (password) VALUES (?)", value)
	db.Exec(query, value)
}

// SQL inference must neither duplicate nor stop existing password-source flow.
func existingInsertSources(db *sql.DB, password string, value string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (password) VALUES (?)", password)                // $ Alert[go/cleartext-password-storage-database]
	acct := Account{Password: value}                                              // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (password) VALUES (?)", value)                   // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (password) VALUES (?)", acct.Password)           // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members (password) VALUES (?)", acct.Password+" suffix") // $ Alert[go/cleartext-password-storage-database]
}

func uppercaseInsert(db *sql.DB, value string) {
	db.Exec("INSERT INTO app.Members (PASSWORD) VALUES (?)", value) // $ Alert[go/cleartext-password-storage-database]
}

// Column inference must preserve dominating same-receiver protective writes.
func protectedFieldInsert(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	db.Exec("INSERT INTO members(password) VALUES (?)", acct.Password)
	derived := acct.Password + " suffix"
	db.Exec("INSERT INTO members(password) VALUES (?)", derived)
}

func overwrittenFieldInsert(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	acct.Password = value
	db.Exec("INSERT INTO members(password) VALUES (?)", acct.Password) // $ Alert[go/cleartext-password-storage-database]
}

// A protected operand cannot hide another operand containing plaintext.
func mixedFieldInsert(db *sql.DB, acct Account, value string) {
	acct.Password = Encrypt(value)
	db.Exec("INSERT INTO members(password) VALUES (?)", acct.Password+":"+value) // $ Alert[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO members(password) VALUES (?)", value+":"+acct.Password) // $ Alert[go/cleartext-password-storage-database]
}
