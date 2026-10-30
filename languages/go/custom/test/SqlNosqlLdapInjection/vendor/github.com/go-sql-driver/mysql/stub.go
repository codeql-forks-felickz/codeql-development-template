// Package mysql is a minimal stub of github.com/go-sql-driver/mysql for testing.
package mysql

type Config struct {
	User                 string
	Passwd               string
	Net                  string
	Addr                 string
	DBName               string
	Params               map[string]string
	AllowNativePasswords bool
	MultiStatements      bool
	ParseTime            bool
}

func NewConfig() *Config { return &Config{} }

func (cfg *Config) FormatDSN() string { return "" }

func ParseDSN(dsn string) (*Config, error) { return nil, nil }
