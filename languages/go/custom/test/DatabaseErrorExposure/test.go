package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

var db *sql.DB

func checkDatabase() (bool, error) {
	_, err := db.Exec("SELECT 1 FROM users LIMIT 1") // $ Source
	if err != nil {
		return false, err
	}
	return true, nil
}

func toHTML(text string) template.HTML {
	return template.HTML(text)
}

func render(w http.ResponseWriter, name string, data map[string]interface{}) {
	t := template.Must(template.ParseGlob("templates/*"))
	t.ExecuteTemplate(w, name, data) // $ Alert
}

// The database error message is embedded into an HTML snippet that is rendered by a template.
func setupViewHandler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	ok, err := checkDatabase()
	if !ok || err != nil {
		info := fmt.Sprintf(`<div id="info" class="alert alert-danger">%s</div>`, err.Error())
		data["error"] = toHTML(info)
	} else {
		data["error"] = toHTML(`<div id="info" class="alert alert-success">Connection Success</div>`)
	}
	render(w, "setup", data)
}

// The database error message is sent with `http.Error`.
func listHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM items") // $ Source
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError) // $ Alert
		return
	}
	defer rows.Close()
}

// The database error is formatted directly into the response.
func getHandler(w http.ResponseWriter, r *http.Request) {
	var name string
	err := db.QueryRow("SELECT name FROM items WHERE id = ?", r.FormValue("id")).Scan(&name) // $ Source
	if err != nil {
		fmt.Fprintf(w, "query failed: %v", err) // $ Alert
		return
	}
	fmt.Fprint(w, name)
}

// The database error message is serialized into a JSON response.
func openHandler(w http.ResponseWriter, r *http.Request) {
	_, err := sql.Open("mysql", "user:pass@tcp(db:3306)/app") // $ Source
	if err != nil {
		b, _ := json.Marshal(map[string]string{"status": "0", "message": err.Error()})
		w.Write(b) // $ Alert
	}
}

// SAFE: the database error is only logged and a generic message is returned.
func safeLoggedHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("DELETE FROM sessions")
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// SAFE: only a boolean derived from the database error reaches the response.
func safeNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	var name string
	err := db.QueryRow("SELECT name FROM items WHERE id = 1").Scan(&name)
	notFound := errors.Is(err, sql.ErrNoRows)
	fmt.Fprintf(w, "not found: %t", notFound)
}

// SAFE: the error does not come from a database operation.
func safeParseHandler(w http.ResponseWriter, r *http.Request) {
	_, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// SAFE: a static message is rendered when the database check fails.
func safeSetupViewHandler(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	if ok, err := checkDatabase(); !ok || err != nil {
		data["error"] = "Database is not available"
	}
	render(w, "setup", data)
}

func main() {}
