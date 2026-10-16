package main

import (
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"golang.org/x/crypto/bcrypt"
)

// UserData mirrors a registration payload bound from an HTTP request.
type UserData struct {
	Username       string `json:"user" bson:"username"`
	Password       string `json:"pass" bson:"password"`
	RepeatPassword string `json:"passcheck"`
	UserID         string `bson:"userID"`
}

type DB struct {
	Session *mgo.Session
}

// Insert is an application wrapper around the driver call.
func (db *DB) Insert(obj interface{}, collection string) error {
	c := db.Session.DB("").C(collection)
	return c.Insert(obj) // $ Alert[go/cleartext-password-storage-database]
}

// RegisterUser stores the supplied password directly in MongoDB.
func RegisterUser(session *DB, userData UserData) error {
	newUserData := bson.M{
		"username": userData.Username,
		"password": userData.Password, // $ Source[go/cleartext-password-storage-database]
		"userID":   userData.UserID,
	}
	return session.Insert(newUserData, "users")
}

// ChangePassword updates the stored password in clear text.
func ChangePassword(c *mgo.Collection, username string, newPassword string) error { // $ Source[go/cleartext-password-storage-database]
	return c.Update(bson.M{"username": username}, bson.M{"$set": bson.M{"password": newPassword}}) // $ Alert[go/cleartext-password-storage-database]
}

// Negative cases.

// RegisterUserHashed stores a bcrypt hash instead of the password.
func RegisterUserHashed(c *mgo.Collection, userData UserData) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return c.Insert(bson.M{"username": userData.Username, "password": string(hashed)})
}

// RegisterUserHashedField overwrites the password field with its hash before storing it.
func RegisterUserHashedField(c *mgo.Collection, userData UserData) error {
	h, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	userData.Password = string(h)
	return c.Insert(bson.M{"username": userData.Username, "password": userData.Password})
}

// Passwords used only as a lookup filter are not written to the database.
func UpdateLastLogin(c *mgo.Collection, username string) error {
	return c.Update(bson.M{"username": username}, bson.M{"$set": bson.M{"lastLogin": "now"}})
}

func main() {}
