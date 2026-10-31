const express = require('express')
const db = require('./db')

const app = express()

app.get('/users', function (req, res) {
  db.query('SELECT * FROM users')
    .then((rows) => res.json(rows))
    .catch((err) => res.status(500).send(err.stack)) // $ Alert
})

app.get('/orders', function (req, res) {
  db.query('SELECT * FROM orders').then(
    (rows) => res.json(rows),
    (reason) => res.status(500).json({ message: reason.message }) // $ Alert
  )
})

app.get('/items', function (req, res) {
  db.query('SELECT * FROM items')
    .then((rows) => res.json(rows))
    .catch((err) => {
      console.error(err)
      res.status(500).json({ error: 'Internal error' })
    })
})

app.get('/legacy', function (req, res) {
  try {
    res.json(db.querySync('SELECT 1'))
  } catch (e) { // $ Source
    res.status(500).send(e.stack) // $ Alert
  }
})

app.listen(3002)
