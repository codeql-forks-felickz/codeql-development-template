const mongoose = require("mongoose");

// Reduced from the Goatlin API: the schema declares a `password` path, and nothing
// (no setter, `pre` hook or plugin) hashes it before it is saved.
const accountSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now() }
});

module.exports = new mongoose.model("Account", accountSchema);
