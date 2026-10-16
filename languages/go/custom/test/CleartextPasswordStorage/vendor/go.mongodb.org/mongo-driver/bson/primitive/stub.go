// Package primitive is a minimal stub of go.mongodb.org/mongo-driver/bson/primitive for testing.
package primitive

type E struct {
	Key   string
	Value interface{}
}

type D []E

type M map[string]interface{}
