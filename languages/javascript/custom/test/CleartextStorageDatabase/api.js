const express = require("express");
const bcrypt = require("bcrypt");
const MongoClient = require("mongodb").MongoClient;

const app = express();
app.use(express.json());

// Reduced from the Pixi registration endpoint: a user-supplied password is stored
// under a `password` field even though the request parameter is just called `pass`.
function api_register(user, pass, req, res) {
    MongoClient.connect("mongodb://localhost/pixidb", function (err, db) {
        db.collection("users").insert({
            email: user,
            password: pass, // $ Alert
            name: req.body.name
        }, function (err, result) {
            res.status(200).json({ ok: !err });
        });
    });
}

app.post("/api/register", function (req, res) {
    api_register(req.body.user, req.body.pass, req, res); // $ Source
});

// Safe: the password is hashed with a password KDF before it is stored.
app.post("/api/register-hashed", async function (req, res) {
    const hash = await bcrypt.hash(req.body.pass, 12);
    const client = await MongoClient.connect("mongodb://localhost/pixidb");
    await client.db().collection("users").insertOne({ email: req.body.user, password: hash });
    res.end();
});

// Safe: user-supplied data that is not sensitive is stored.
app.post("/api/pictures", async function (req, res) {
    const client = await MongoClient.connect("mongodb://localhost/pixidb");
    await client.db().collection("pictures").insertOne({ title: req.body.title, description: req.body.description });
    res.end();
});

app.listen(8080);
