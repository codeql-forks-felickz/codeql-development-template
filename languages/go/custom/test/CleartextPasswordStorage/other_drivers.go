package main

import (
	"context"
	"database/sql"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Account struct {
	Name         string
	Password     string
	PasswordHint string
}

type SignupRequest struct {
	Name     string
	Password string
}

func mongoDriverInsert(ctx context.Context, coll *mongo.Collection, name string, password string) { // $ Source[go/cleartext-password-storage-database]
	coll.InsertOne(ctx, bson.D{{Key: "name", Value: name}, {Key: "password", Value: password}}) // $ Alert[go/cleartext-password-storage-database]
}

func mongoDriverStruct(ctx context.Context, coll *mongo.Collection, req SignupRequest) {
	var acct Account
	acct.Name = req.Name
	acct.Password = req.Password // $ Source[go/cleartext-password-storage-database]
	coll.InsertOne(ctx, acct) // $ Alert[go/cleartext-password-storage-database]
}

func mongoDriverUpdate(ctx context.Context, coll *mongo.Collection, id string, passwd string) { // $ Source[go/cleartext-password-storage-database]
	coll.UpdateByID(ctx, id, bson.M{"$set": bson.M{"passwd": passwd}}) // $ Alert[go/cleartext-password-storage-database]
}

func sqlInsert(db *sql.DB, name string, password string) { // $ Source[go/cleartext-password-storage-database]
	db.Exec("INSERT INTO users(name, password) VALUES(?, ?)", name, password) // $ Alert[go/cleartext-password-storage-database]
}

func sqlPreparedUpdate(ctx context.Context, stmt *sql.Stmt, name string, userPassword string) { // $ Source[go/cleartext-password-storage-database]
	stmt.ExecContext(ctx, userPassword, name) // $ Alert[go/cleartext-password-storage-database]
}

func gormCreate(db *gorm.DB, name string, pw string) {
	db.Create(&Account{Name: name, Password: pw}) // $ Alert[go/cleartext-password-storage-database]
}

// Negative cases.

func gormCreateHashed(db *gorm.DB, name string, pw string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	acct := Account{Name: name}
	acct.Password = string(h)
	db.Create(&acct)
	return nil
}

func gormHint(db *gorm.DB, name string, passwordHint string) {
	db.Create(&Account{Name: name, PasswordHint: passwordHint})
}

func sqlLookup(db *sql.DB, name string, password string) {
	db.Query("SELECT id FROM users WHERE name = ? AND password = ?", name, password)
	db.Exec("DELETE FROM users WHERE name = ? AND password = ?", name, password)
}

func mongoLookup(ctx context.Context, coll *mongo.Collection, name string, password string) {
	coll.FindOne(ctx, bson.M{"name": name, "password": password})
}

func sqlInsertHashed(db *sql.DB, name string, password string) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users(name, password) VALUES(?, ?)", name, hashedPassword)
}
