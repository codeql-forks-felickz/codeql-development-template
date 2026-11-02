const express = require('express');
const { Sequelize, DataTypes } = require('sequelize');
const _ = require('lodash');

const sequelize = new Sequelize('sqlite::memory:');
const User = sequelize.define('User', {
  username: DataTypes.STRING,
  role: DataTypes.STRING
});

const app = express();
app.use(express.json());

app.post('/users', async (req, res) => {
  const user = User.build(req.body); // $ Alert
  await user.save();
  res.json(user);
});

app.put('/users/:id', async (req, res) => {
  await User.update(req.body, { where: { id: req.params.id } }); // $ Alert
  res.end();
});

app.get('/users', async (req, res) => {
  const users = await User.findAll({ where: { username: JSON.parse(req.query.username) } }); // $ Alert
  res.json(users);
});

// Safe: explicit fields with a fixed role.
app.post('/users/safe', async (req, res) => {
  const user = await User.create({ username: req.body.username, role: 'user' });
  res.json(user);
});

// Safe: typeof check guarantees a primitive value.
app.get('/users/safe', async (req, res) => {
  const username = JSON.parse(req.query.username);
  if (typeof username !== 'string') {
    return res.status(400).end();
  }
  const users = await User.findAll({ where: { username } });
  res.json(users);
});

app.post('/users/fields-safe', async (req, res) => {
  await User.create(req.body, { fields: ['username'] });
  await User.bulkCreate([req.body], { fields: ['username'] });
  await User.upsert(req.body, { fields: ['username'] });
  const user = await User.findByPk(req.params.id);
  await user.update(req.body, { fields: ['username'] });
  res.end();
});

app.put('/users/fields-update', async (req, res) => {
  await User.update(req.body, {
    fields: ['username'],
    where: _.pick(req.body, ['id']) // $ Alert
  });
  res.end();
});

app.post('/users/fields-dynamic', async (req, res) => {
  await User.create(req.body, { fields: [req.body.field] }); // $ Alert
  res.end();
});

app.get('/users/projected-condition', async (req, res) => {
  const users = await User.findAll({ where: _.pick(req.body, ['id']) }); // $ Alert
  res.json(users);
});
