const express = require("express");
const mongoose = require("mongoose");

const Account = mongoose.model(
  "Account",
  new mongoose.Schema({ email: String, password: String })
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
  const account = await Account.findById(req.params.id);
  account.email = req.query.email;
  const saved = await account.save(); // $ Source
  res.json(saved.toObject()); // $ Alert
});

// Safe: the schema removes the password in a `toJSON` transform.
app.get("/hidden/:id", async (req, res) => {
  res.json(await HiddenAccount.findById(req.params.id));
});

// Safe: the projection excludes the password.
app.get("/emails", async (req, res) => {
  res.json(await Account.find({}, "email"));
});
