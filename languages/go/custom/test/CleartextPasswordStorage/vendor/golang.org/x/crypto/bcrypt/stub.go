// Package bcrypt is a minimal stub of golang.org/x/crypto/bcrypt for testing.
package bcrypt

const DefaultCost int = 10

func GenerateFromPassword(password []byte, cost int) ([]byte, error) { return nil, nil }

func CompareHashAndPassword(hashedPassword, password []byte) error { return nil }
