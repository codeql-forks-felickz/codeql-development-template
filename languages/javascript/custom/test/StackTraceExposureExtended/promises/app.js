const express = require('express')
const db = require('./db')

const app = express()
const env = process.env.NODE_ENV

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

if (env === 'development') {
  app.get('/development-only', function (req, res) {
    db.query('SELECT * FROM users')
      .catch((err) => res.status(500).send(err.stack))
  })
}

app.get('/request-controlled-development', function (req, res) {
  db.query('SELECT * FROM users').catch((err) => { // $ Source
    if (req.query.mode === 'development') {
      res.status(500).send(err.stack) // $ Alert
    }
  })
})

app.listen(3002)
