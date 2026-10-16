package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Reduced from the govwa finding: a cookie or form value is interpolated with fmt.Sprintf.
var govwaDB *sql.DB

type govwaProfile struct{ Name string }

func govwaGetCookie(r *http.Request, name string) string {
	cookie, _ := r.Cookie(name) // $ Source
	return cookie.Value
}

func (p *govwaProfile) UnsafeQueryGetData(uid string) {
	getProfileSql := fmt.Sprintf(`SELECT p.full_name FROM Profile as p, Users as u
		where p.user_id = u.id and u.id=%s`, uid)
	govwaDB.Query(getProfileSql) // $ Alert
}

func (p *govwaProfile) SafeQueryGetData(uid string) {
	stmt, _ := govwaDB.Prepare(`SELECT p.full_name FROM Profile as p, Users as u
		where p.user_id = u.id and u.id=?`)
	stmt.QueryRow(uid)
}

func govwaSqli1Handler(w http.ResponseWriter, r *http.Request) {
	uid := govwaGetCookie(r, "Uid")
	p := &govwaProfile{}
	p.UnsafeQueryGetData(uid)
	p.SafeQueryGetData(uid)
}

func govwaSqli2Handler(w http.ResponseWriter, r *http.Request) {
	uid := r.FormValue("uid") // $ Source
	p := &govwaProfile{}
	p.UnsafeQueryGetData(uid)
	p.SafeQueryGetData(uid)
}
