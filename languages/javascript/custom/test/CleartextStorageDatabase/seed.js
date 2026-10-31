const mongoose = require("mongoose");
const MongoClient = require("mongodb").MongoClient;
const Schema = mongoose.Schema;

// Reduced from nodejs-goof: the model is registered once and later looked up by name,
// and a default administrator is seeded with a hard-coded clear-text password.
const User = new Schema({
    username: String,
    password: String
});
mongoose.model("User", User);

const SeedUser = mongoose.model("User");
SeedUser.find({ username: "admin@example.com" }).exec(function (err, users) {
    if (users.length === 0) {
        new SeedUser({ username: "admin@example.com", password: "SuperSecretPassword" }).save(); // $ Alert
    }
});

// Reduced from secDevLabs stegonography: a default administrator inserted with the driver.
MongoClient.connect("mongodb://db:27017/stego", function (err, client) {
    const dbo = client.db("stego");
    const myobj = { username: "admin", password: "admin" }; // $ Alert
    dbo.collection("users").insertOne(myobj);

    // Safe: the seeded value is already a bcrypt hash.
    dbo.collection("users").insertOne({
        username: "operator",
        password: "$2b$12$C6UzMDM.H6dfI/f/IKcEeO5Q7YwX9eFh5x5b0c5Oq4e2bXJzT1Vay"
    });

    // Safe: an empty placeholder is not a credential.
    dbo.collection("users").insertOne({ username: "guest", password: "" });

    // Safe: a hard-coded value in a non-sensitive field.
    dbo.collection("settings").insertOne({ theme: "dark" });
});
