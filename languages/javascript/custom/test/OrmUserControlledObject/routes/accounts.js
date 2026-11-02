const express = require('express');
const _ = require('lodash');
const Account = require('../models/account');
const Note = require('../models/note');

const router = express.Router();
router.use(express.json());

router.post('/accounts', async (req, res) => {
  const account = new Account(req.body); // $ Alert
  await account.save();
  res.status(201).end();
});

router.post('/accounts/create', async (req, res) => {
  await Account.create(req.body); // $ Alert
  res.status(201).end();
});

router.post('/accounts/bulk', async (req, res) => {
  const data = req.body; // $ Source
  await Account.insertMany(data.accounts); // $ Alert
  res.status(201).end();
});

router.post('/accounts/import', async (req, res) => {
  const profile = JSON.parse(req.query.profile); // $ Source
  await Account.create(profile); // $ Alert
  res.status(201).end();
});

// Not reported here: the update document is already reported by `js/sql-injection`.
router.put('/accounts/:username/notes/:note', async (req, res) => {
  const rawNote = {
    ...req.body,
    id: req.params.note,
    owner: req.params.username
  };
  await Note.findOneAndUpdate({ owner: req.params.username, id: req.params.note }, rawNote, {
    new: true,
    upsert: true
  });
  res.status(204).end();
});

router.patch('/accounts/:id', async (req, res) => {
  const account = await Account.findById(req.params.id);
  account.set(req.body); // $ Alert
  await account.save();
  res.status(204).end();
});

// Safe: only explicitly selected fields are passed to the model.
router.post('/accounts/safe', async (req, res) => {
  const account = new Account({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password
  });
  await account.save();
  res.status(201).end();
});

// Safe: allow-listed fields via lodash `pick`.
router.post('/accounts/safe-pick', async (req, res) => {
  await Account.create(_.pick(req.body, ['name', 'email', 'password']));
  res.status(201).end();
});

// Safe: update document is built from constant keys.
router.put('/accounts/:id/name', async (req, res) => {
  await Account.updateOne({ _id: req.params.id }, { $set: { name: String(req.body.name) } });
  res.status(204).end();
});

// Safe: a string value cannot introduce extra fields.
router.post('/accounts/by-name/:name', async (req, res) => {
  await Account.create({ name: req.params.name, email: 'x@example.com', password: 'p' });
  res.status(201).end();
});

module.exports = router;
