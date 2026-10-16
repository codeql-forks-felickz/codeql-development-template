package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Reduced from the go-test-bench finding: the vulnerable handler is stored in a
// function-typed struct field and invoked indirectly through that field.
type testBenchHandlerFn func(safety string, payload string) string

type testBenchSink struct {
	Name    string
	Handler testBenchHandlerFn
}

type testBenchRoute struct {
	Base  string
	Sinks []*testBenchSink
}

var testBenchAllRoutes []testBenchRoute

func testBenchRegister(r testBenchRoute) {
	testBenchAllRoutes = append(testBenchAllRoutes, r)
}

type testBenchSqliteInj struct {
	db *sql.DB
}

func (si testBenchSqliteInj) execHandler(mode string, in string) string {
	switch mode {
	case "unsafe":
		query := fmt.Sprintf("SELECT '%s' as '%s'", in, "test")
		si.db.Exec(query) // $ Alert
	case "safe":
		si.db.Exec("SELECT ? as ?", in, "test")
	}
	return ""
}

func testBenchRegisterRoutes(db *sql.DB) {
	testBenchRegister(testBenchRoute{
		Base: "sqlInjection",
		Sinks: []*testBenchSink{
			{Name: "sqlite3.exec", Handler: testBenchSqliteInj{db}.execHandler},
		},
	})
}

func testBenchNewHandler(v testBenchRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, s := range v.Sinks {
			in := r.URL.Query().Get("input") // $ Source
			s.Handler("unsafe", in)
		}
	}
}

func testBenchSetup(db *sql.DB) {
	testBenchRegisterRoutes(db)
	for _, r := range testBenchAllRoutes {
		http.HandleFunc("/"+r.Base+"/", testBenchNewHandler(r))
	}
}

// Negative: only the field holding the parameterized function is invoked with
// tainted data, so the vulnerable function stored in the other field must not alert.
type testBenchDualSink struct {
	Unsafe func(string)
	Safe   func(string)
}

func testBenchDualSetup(db *sql.DB) {
	d := testBenchDualSink{
		Unsafe: func(in string) { db.Exec("SELECT '" + in + "'") },
		Safe:   func(in string) { db.Exec("SELECT ?", in) },
	}
	http.HandleFunc("/dual", func(w http.ResponseWriter, r *http.Request) {
		d.Safe(r.URL.Query().Get("input"))
		d.Unsafe("constant")
	})
}

// Positive: a named function assigned to a function-typed field and invoked
// through that field from a closure.
type testBenchAssignedSink struct {
	Run func(db *sql.DB, in string)
}

func testBenchRunQuery(db *sql.DB, in string) {
	db.Query("SELECT '" + in + "'") // $ Alert
}

func testBenchAssignedSetup(db *sql.DB) {
	var s testBenchAssignedSink
	s.Run = testBenchRunQuery
	http.HandleFunc("/assigned", func(w http.ResponseWriter, r *http.Request) {
		s.Run(db, r.FormValue("input")) // $ Source
	})
}
