const express = require("express");
const mongoose = require("mongoose");

const Account = mongoose.model(
  "Account",
  new mongoose.Schema({ email: String, ssn: String, password: String })
);

const hiddenSchema = new mongoose.Schema({ email: String, password: String });
hiddenSchema.set("toJSON", {
  transform: (doc, ret) => {
    delete ret.password;
    return ret;
  }
});
const HiddenAccount = mongoose.model("HiddenAccount", hiddenSchema);

const app = express();

app.get("/accounts", (req, res) => {
  Account.find({}).exec((err, accounts) => { // $ Source
    res.send(accounts); // $ Alert
  });
});

app.get("/accounts/:id", async (req, res) => {
  const account = await Account.findById(req.params.id); // $ Source
  account.email = req.query.email;
  const saved = await account.save(); // $ Source
  res.json(saved.toObject()); // $ Alert
  res.json(account.get()); // $ Alert
  res.json(account.get("password")); // $ Alert
  res.json(account.get("email")); // Safe: only a non-sensitive field is returned.
  res.json(account.ssn); // Safe: a private field is not a password disclosure.
});

app.get("/accounts/options", async (req, res) => {
  const account = await Account.findOne({ email: req.query.email }, null, { lean: true }); // $ Source
  res.json(account); // $ Alert
});

// Safe: the schema removes the password in a `toJSON` transform.
app.get("/hidden/:id", async (req, res) => {
  res.json(await HiddenAccount.findById(req.params.id));
});

// Safe: the projection excludes the password.
app.get("/emails", async (req, res) => {
  res.json(await Account.find({}, "email"));
});
