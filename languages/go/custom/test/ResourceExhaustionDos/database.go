package main

import (
	"database/sql"
	"database/sql/driver"
	"net/http"
)

type User struct {
	ID   int
	Name string
}

type Repo struct {
	db *sql.DB
}

var globalDB *sql.DB
var pingCallback func() error

// BAD: a new connection pool is opened on every call and never closed.
// Closing only `rows` does not release the pool or its goroutine.
func getUsers(search string) []User {
	db, err := sql.Open("sqlite3", "data/users.db") // $ Alert
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT id, name FROM user WHERE name LIKE ?", "%"+search+"%")
	if err != nil {
		panic(err)
	}
	var results []User
	for rows.Next() {
		var user User
		_ = rows.Scan(&user.ID, &user.Name)
		results = append(results, user)
	}
	rows.Close()
	return results
}

// BAD: same leak inside a request handler.
func countHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite3", r.FormValue("dsn")) // $ Alert
	db.SetMaxOpenConns(1)
	row := db.QueryRow("SELECT COUNT(*) FROM user")
	var n int
	row.Scan(&n)
}

// BAD: sql.OpenDB also creates a pool that must be closed.
func queryWithConnector(c driver.Connector) {
	db := sql.OpenDB(c) // $ Alert
	db.Exec("SELECT 1")
}

// BAD: the result is assigned with `=` to a previously declared local.
func pingDatabase() error {
	var db *sql.DB
	var err error
	db, err = sql.Open("sqlite3", "data/users.db") // $ Alert
	if err != nil {
		return err
	}
	return db.Ping()
}

// GOOD: deferred Close.
func getUsersDeferClose(search string) int {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	var n int
	db.QueryRow("SELECT COUNT(*) FROM user WHERE name = ?", search).Scan(&n)
	return n
}

// GOOD: explicit Close.
func getUsersExplicitClose() {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		return
	}
	db.Exec("DELETE FROM user")
	db.Close()
}

// GOOD: Close in a deferred closure.
func getUsersClosureClose() {
	db, _ := sql.Open("sqlite3", "data/users.db")
	defer func() {
		_ = db.Close()
	}()
	db.Ping()
}

// GOOD: ownership is transferred to the caller.
func openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		return nil, err
	}
	return db, nil
}

// GOOD: ownership is transferred to the caller (direct return).
func openDBDirect() (*sql.DB, error) {
	return sql.Open("sqlite3", "data/users.db")
}

// GOOD: stored in a global and reused.
func initGlobal() {
	db, err := sql.Open("sqlite3", "data/users.db")
	if err != nil {
		panic(err)
	}
	globalDB = db
}

// GOOD: stored in a struct that owns it.
func newRepo() *Repo {
	db, _ := sql.Open("sqlite3", "data/users.db")
	return &Repo{db: db}
}

// GOOD: stored in a struct field via assignment.
func (r *Repo) reconnect() {
	db, _ := sql.Open("sqlite3", "data/users.db")
	r.db = db
}

// GOOD: passed to another function that takes ownership.
func useWithHelper() {
	db, _ := sql.Open("sqlite3", "data/users.db")
	register(db)
}

func register(db *sql.DB) {
	globalDB = db
}

// GOOD: sent on a channel.
func sendDB(ch chan *sql.DB) {
	db, _ := sql.Open("sqlite3", "data/users.db")
	ch <- db
}

// GOOD: opened once at startup; the pool lives for the life of the process.
func setupFromMain() {
	db, _ := sql.Open("sqlite3", "data/users.db")
	db.Exec("CREATE TABLE IF NOT EXISTS user(id INTEGER, name TEXT)")
}

// BAD: helper is called repeatedly from a loop in main.
func pollOnce() {
	db, _ := sql.Open("sqlite3", "data/users.db") // $ Alert
	db.Ping()
}

// BAD: this helper is called repeatedly from a loop condition.
func pollCondition(i int) bool {
	db, _ := sql.Open("sqlite3", "data/users.db") // $ Alert
	db.Ping()
	return i < 10
}

// BAD: this helper is called repeatedly from a loop post statement.
func pollPost() {
	db, _ := sql.Open("sqlite3", "data/users.db") // $ Alert
	db.Ping()
}

// GOOD: the returned closure retains the pool.
func openDBClosure() func() error {
	db, _ := sql.Open("sqlite3", "data/users.db")
	return func() error {
		return db.Ping()
	}
}

// GOOD: the stored method value retains the pool.
func storePingMethod() {
	db, _ := sql.Open("sqlite3", "data/users.db")
	pingCallback = db.Ping
}

func init() {
	// GOOD: init runs once.
	db, _ := sql.Open("sqlite3", "data/users.db")
	db.Ping()
}

func main() {
	// GOOD: opened once in main.
	db, _ := sql.Open("sqlite3", "data/users.db")
	db.Ping()

	setupFromMain()

	for i := 0; i < 10; i++ {
		pollOnce()
		// BAD: a new pool is opened on every loop iteration.
		loopDB, _ := sql.Open("sqlite3", "data/users.db") // $ Alert
		loopDB.Ping()
	}

	for i := 0; pollCondition(i); i++ {
	}
	for i := 0; i < 10; pollPost() {
		i++
	}

	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		getUsers(r.FormValue("search"))
	})
	http.HandleFunc("/count", countHandler)
	http.ListenAndServe(":8080", nil)
}
