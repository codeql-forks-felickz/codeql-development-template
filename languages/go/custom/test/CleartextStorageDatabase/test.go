package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
)

type User struct {
	ID          int
	FirstName   string
	Email       string
	DOB         string
	SSN         string
	Salary      int
	SsnHash     string
	ClassName   string
	AdobeID     string
	DateOfBirth string
}

var db *sql.DB

// Sensitive fields formatted into an INSERT statement.
func seedFormatted(users []User) {
	for i, user := range users {
		q := fmt.Sprintf("INSERT INTO user VALUES (%d, '%s', '%s');", i, user.FirstName, user.SSN) // $ Source
		db.Exec(q)                                                                                 // $ Alert
	}
}

// Sensitive fields passed as bind parameters of an INSERT statement.
func seedParameterized(user User) {
	db.Exec("INSERT INTO user (first_name, dob) VALUES (?, ?)", user.FirstName, user.DOB) // $ Alert
}

// Sensitive data concatenated into an UPDATE statement.
func updateConcatenated(id string, user User) {
	db.Exec("UPDATE user SET date_of_birth = '" + user.DateOfBirth + "' WHERE id = " + id) // $ Alert
}

// Sensitive variable stored through a prepared statement.
func updateSalary(id int, salary int) {
	stmt, _ := db.Prepare("UPDATE employees SET salary = ? WHERE id = ?")
	stmt.Exec(salary, id) // $ Alert
}

// Password read from a request and stored inside a transaction.
func register(ctx context.Context, tx *sql.Tx, r *http.Request) {
	name := r.FormValue("name")
	password := r.FormValue("password")
	tx.ExecContext(ctx, "INSERT INTO users (name, password) VALUES ($1, $2)", name, password) // $ Alert
}

// SAFE: the SSN is hashed before it is stored.
func seedHashed(user User) {
	h := sha256.Sum256([]byte(user.SSN))
	db.Exec("INSERT INTO user (first_name, ssn) VALUES (?, ?)", user.FirstName, hex.EncodeToString(h[:]))
}

// SAFE: the SSN is encrypted before it is stored.
func seedEncrypted(user User) {
	db.Exec("INSERT INTO user (first_name, ssn) VALUES (?, ?)", user.FirstName, encryptField(user.SSN))
}

// SAFE: the SSN is only used to look up a row, not stored.
func lookup(user User) int {
	var id int
	db.QueryRow("SELECT id FROM user WHERE ssn = ?", user.SSN).Scan(&id)
	return id
}

// SAFE: only non-sensitive fields are stored.
func seedPublic(user User) {
	db.Exec("INSERT INTO user (first_name, email, class_name, adobe_id) VALUES (?, ?, ?, ?)", user.FirstName, user.Email, user.ClassName, user.AdobeID)
}

// SAFE: the field name indicates that the value is already hashed.
func seedPrehashed(user User) {
	db.Exec("INSERT INTO user (first_name, ssn) VALUES (?, ?)", user.FirstName, user.SsnHash)
}

func encryptField(s string) string {
	return s
}

func main() {}
