package main

import (
	"context"
	"database/sql"
	"net/http"
)

// Reduced from the go-dvwa finding: a query parameter is concatenated into QueryContext.
func goDvwaGetProducts(ctx context.Context, db *sql.DB, category string) {
	db.QueryContext(ctx, "SELECT * FROM product WHERE category='"+category+"'") // $ Alert
}

func goDvwaGetProductsSafe(ctx context.Context, db *sql.DB, category string) {
	db.QueryContext(ctx, "SELECT * FROM product WHERE category=?", category)
}

func goDvwaRoutes(mux *http.ServeMux, db *sql.DB) {
	mux.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		category := r.FormValue("category") // $ Source
		goDvwaGetProducts(r.Context(), db, category)
		goDvwaGetProductsSafe(r.Context(), db, category)
	})
}
