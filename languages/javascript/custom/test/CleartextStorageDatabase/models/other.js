const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

// Safe: the `password` path has a setter that hashes the value.
const setterAccountSchema = new mongoose.Schema({
    email: String,
    password: { type: String, set: (v) => bcrypt.hashSync(v, 12) }
});

// Not sensitive: the schema has no sensitive paths.
const noteSchema = new mongoose.Schema({
    owner: String,
    title: String,
    body: String
});

module.exports = {
    SetterAccount: mongoose.model("SetterAccount", setterAccountSchema),
    Note: mongoose.model("Note", noteSchema)
};
