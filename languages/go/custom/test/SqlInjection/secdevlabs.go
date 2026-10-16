package main

import (
	"database/sql"
	"fmt"

	"github.com/labstack/echo/v4"
)

// Reduced from the secDevLabs finding: an Echo bound struct field (the original app uses Echo v3; the Context.Bind source model is shared across major versions) is concatenated into a query.
type secDevLabsLoginAttempt struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

func secDevLabsAuthenticateUser(dbConn *sql.DB, user string) {
	query := fmt.Sprint("select * from Users where username = '" + user + "'")
	dbConn.Query(query) // $ Alert
}

func secDevLabsAuthenticateUserSafe(dbConn *sql.DB, user string) {
	dbConn.Query("select * from Users where username = ?", user)
}

func secDevLabsLogin(dbConn *sql.DB) func(c echo.Context) error {
	return func(c echo.Context) error {
		loginAttempt := secDevLabsLoginAttempt{}
		c.Bind(&loginAttempt) // $ Source
		secDevLabsAuthenticateUser(dbConn, loginAttempt.User)
		secDevLabsAuthenticateUserSafe(dbConn, loginAttempt.User)
		return c.String(200, "ok")
	}
}
