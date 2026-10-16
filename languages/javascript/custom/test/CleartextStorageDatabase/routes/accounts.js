const express = require("express");
const bcrypt = require("bcrypt");
const Account = require("../models/account");
const HashedAccount = require("../models/hashed-account");
const { SetterAccount, Note } = require("../models/other");

const router = express.Router();

// Reduced from the Goatlin API: the whole request body (including `password`)
// is persisted through a schema with a clear-text `password` path.
router.post("/accounts", async (req, res) => {
    const account = new Account(req.body); // $ Alert
    await account.save();
    res.status(201).end();
});

router.post("/accounts/bulk", async (req, res) => {
    await Account.create(req.body.accounts); // $ Alert
    res.status(201).end();
});

// A sensitive value written explicitly into a Mongoose document.
router.post("/accounts/explicit", async (req, res) => {
    await Account.create({ email: req.body.email, password: req.body.password }); // $ Alert
    res.status(201).end();
});

router.put("/accounts/:id/password", async (req, res) => {
    await Account.findByIdAndUpdate(req.params.id, { $set: { password: req.body.newPassword } }); // $ Alert
    res.status(204).end();
});

// Safe: the password is hashed before it is persisted.
router.put("/accounts/:id/password-hashed", async (req, res) => {
    const password = await bcrypt.hash(req.body.newPassword, 12);
    await Account.updateOne({ _id: req.params.id }, { password });
    res.status(204).end();
});

// Safe: the schema hashes the password in a `pre('save')` hook.
router.post("/hashed-accounts", async (req, res) => {
    const account = new HashedAccount(req.body);
    await account.save();
    await HashedAccount.create({ email: req.body.email, password: req.body.password });
    res.status(201).end();
});

// Safe: the schema hashes the password with a path setter.
router.post("/setter-accounts", async (req, res) => {
    await new SetterAccount(req.body).save();
    res.status(201).end();
});

// Safe: the schema has no sensitive paths.
router.put("/notes/:id", async (req, res) => {
    await Note.findOneAndUpdate({ _id: req.params.id }, req.body, { upsert: true });
    res.status(204).end();
});

module.exports = router;
