const express = require('express');
const MongoClient = require('mongodb').MongoClient;

const app = express();
const url = 'mongodb://localhost:27017/app';

// Vulnerable: a `$or` sub-document receives a value parsed from the query string,
// so `?search[$ne]=x` turns the equality match into an operator match.
app.get('/admin/users/search', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    db.collection('users').find({ $or: [{ name: req.query.search }, { email: req.query.search }] }).toArray(function (err, users) { // $ Alert
      res.json(users);
    });
  });
});

// Vulnerable: the array of sub-documents is built separately before being used in `$nor`.
app.get('/admin/likes/search', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    const clauses = [{ picture_id: req.query.search }]; // $ Source
    db.collection('likes').find({ $nor: clauses }).toArray(function (err, likes) { // $ Alert
      res.json(likes);
    });
  });
});

// Vulnerable: sub-documents are pushed onto the `$or` array.
app.get('/admin/comments/search', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    const clauses = [];
    clauses.push({ author: req.query.author }); // $ Source
    db.collection('comments').find({ $or: clauses }).toArray(function (err, comments) { // $ Alert
      res.json(comments);
    });
  });
});

// Vulnerable: logical operators nested inside another logical operator.
app.get('/admin/pictures/search', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    const query = { $and: [{ owner: 'admin' }, { $or: [{ title: req.query.title }] }] }; // $ Source
    db.collection('pictures').findOne(query, function (err, picture) { // $ Alert
      res.json(picture);
    });
  });
});

// Safe: the value is coerced to a string before being placed in the sub-document.
app.get('/safe/string', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    db.collection('users').find({ $or: [{ name: String(req.query.search) }] }).toArray(function (err, users) {
      res.json(users);
    });
  });
});

// Safe: the value is checked to be a string before use.
app.get('/safe/typeof', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    const search = req.query.search;
    if (typeof search !== 'string') {
      return res.status(400).end();
    }
    db.collection('users').find({ $or: [{ name: search }, { email: search }] }).toArray(function (err, users) {
      res.json(users);
    });
  });
});

// Not reported by this query: arrays outside of `$and`/`$or`/`$nor` are matched literally.
app.get('/safe/in', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    db.collection('users').find({ name: { $in: [req.query.search] } }).toArray(function (err, users) {
      res.json(users);
    });
  });
});

// Not reported by this query: a top-level field is already reported by `js/sql-injection`.
app.get('/stock/direct', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    db.collection('users').find({ name: req.query.search }).toArray(function (err, users) {
      res.json(users);
    });
  });
});

// Not reported by this query: string concatenation into `$where` is reported by `js/code-injection`.
app.get('/stock/where', function (req, res) {
  MongoClient.connect(url, function (err, db) {
    db.collection('orders').find({ $where: "this.orderId === '" + req.params.id + "'" }).toArray(function (err, orders) {
      res.json(orders);
    });
  });
});

app.listen(3000);
