const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

// Safe: a `pre('save')` hook hashes the password before it is persisted.
const hashedAccountSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

hashedAccountSchema.pre("save", async function () {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, 12);
    }
});

module.exports = mongoose.model("HashedAccount", hashedAccountSchema);
