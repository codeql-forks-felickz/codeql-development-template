// Package gorm is a minimal stub of gorm.io/gorm for testing.
package gorm

type DB struct{}

func (db *DB) Create(value interface{}) (tx *DB) { return db }

func (db *DB) Save(value interface{}) (tx *DB) { return db }

func (db *DB) Updates(values interface{}) (tx *DB) { return db }

func (db *DB) Update(column string, value interface{}) (tx *DB) { return db }

func (db *DB) Where(query interface{}, args ...interface{}) (tx *DB) { return db }

func (db *DB) First(dest interface{}, conds ...interface{}) (tx *DB) { return db }
