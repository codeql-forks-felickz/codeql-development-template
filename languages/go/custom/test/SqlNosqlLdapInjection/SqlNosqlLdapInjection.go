package statusservice

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
)

// Reduced from the reported pattern: multiStatements enabled through Config.Params.
func paramsIndexWrite() (*sql.DB, error) {
	cfg := mysql.NewConfig()
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["multiStatements"] = "true" // $ Alert
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MARIADB_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = os.Getenv("MARIADB_SERVICE")
	return sql.Open("mysql", cfg.FormatDSN())
}

func paramsIndexWriteNumeric(cfg *mysql.Config) {
	cfg.Params["multiStatements"] = "1" // $ Alert
}

func paramsMapLiteral() *mysql.Config {
	return &mysql.Config{
		User:   "root",
		Params: map[string]string{"multiStatements": "true"}, // $ Alert
	}
}

func paramsFieldAssignMapLiteral(cfg *mysql.Config) {
	cfg.Params = map[string]string{"charset": "utf8mb4", "multiStatements": "True"} // $ Alert
}

func paramsAliasedLocal(cfg *mysql.Config) {
	p := cfg.Params
	p["multiStatements"] = "TRUE" // $ Alert
}

func paramsLocalMapAssigned(cfg *mysql.Config) {
	m := make(map[string]string)
	m["multiStatements"] = "true" // $ Alert
	cfg.Params = m
}

func multiStatementsField() *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.MultiStatements = true // $ Alert
	return cfg
}

func multiStatementsFieldLiteral() *mysql.Config {
	return &mysql.Config{User: "root", MultiStatements: true} // $ Alert
}

func dsnString() (*sql.DB, error) {
	return sql.Open("mysql", "root:secret@tcp(db:3306)/app?parseTime=true&multiStatements=true") // $ Alert
}

func dsnFragment(base string) (*mysql.Config, error) {
	return mysql.ParseDSN(base + "?multiStatements=1") // $ Alert
}

func dsnDuplicateLastDisabled() (*mysql.Config, error) {
	return mysql.ParseDSN("root:secret@tcp(db:3306)/app?multiStatements=true&multiStatements=false")
}

func dsnDuplicateLastEnabled() (*mysql.Config, error) {
	return mysql.ParseDSN("root:secret@tcp(db:3306)/app?multiStatements=false&multiStatements=true") // $ Alert
}

// Safe counterparts: multiStatements disabled or not set.

func safeParamsDisabled(cfg *mysql.Config) {
	cfg.Params["multiStatements"] = "false"
	cfg.Params["parseTime"] = "true"
}

func safeMapLiteral() *mysql.Config {
	return &mysql.Config{Params: map[string]string{"multiStatements": "0", "charset": "utf8mb4"}}
}

func safeField() *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.MultiStatements = false
	cfg.ParseTime = true
	return cfg
}

func safeDsn() (*sql.DB, error) {
	return sql.Open("mysql", "root:secret@tcp(db:3306)/app?parseTime=true&multiStatements=false")
}

func safeUnrelatedMap() map[string]string {
	// Not a mysql.Config; must not alert.
	return map[string]string{"multiStatements": "true"}
}

type otherConfig struct {
	MultiStatements bool
}

func safeUnrelatedStruct() otherConfig {
	return otherConfig{MultiStatements: true}
}
