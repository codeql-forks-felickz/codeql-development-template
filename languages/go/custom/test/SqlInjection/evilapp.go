package main

import (
	"database/sql"
	"net/http"
)

// Reduced from the evil-app finding: a POST form value is concatenated into a LIKE pattern.
func evilAppGetUsers(db *sql.DB, search string) {
	q := "SELECT * FROM user WHERE (first_name LIKE '%" + search + "%' OR last_name LIKE '%" + search + "%') AND admin == 'false';"
	db.Query(q) // $ Alert
}

func evilAppGetUsersSafe(db *sql.DB, search string) {
	db.Query("SELECT * FROM user WHERE (first_name LIKE ? OR last_name LIKE ?) AND admin == 'false';", "%"+search+"%", "%"+search+"%")
}

func evilAppUsersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		searchQuery := r.PostFormValue("search") // $ Source
		if searchQuery != "" {
			evilAppGetUsers(db, searchQuery)
			evilAppGetUsersSafe(db, searchQuery)
		}
	}
}
