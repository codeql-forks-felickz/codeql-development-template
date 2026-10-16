// Package mgo is a minimal stub of gopkg.in/mgo.v2 for testing.
package mgo

type Session struct{}

func (s *Session) DB(name string) *Database { return &Database{} }

type Database struct{}

func (db *Database) C(name string) *Collection { return &Collection{} }

type ChangeInfo struct{}

type Collection struct{}

func (c *Collection) Insert(docs ...interface{}) error { return nil }

func (c *Collection) Update(selector interface{}, update interface{}) error { return nil }

func (c *Collection) UpdateId(id interface{}, update interface{}) error { return nil }

func (c *Collection) UpdateAll(selector interface{}, update interface{}) (*ChangeInfo, error) {
	return nil, nil
}

func (c *Collection) Upsert(selector interface{}, update interface{}) (*ChangeInfo, error) {
	return nil, nil
}

func (c *Collection) UpsertId(id interface{}, update interface{}) (*ChangeInfo, error) {
	return nil, nil
}
