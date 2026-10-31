const swig = require('swig')
const express = require('express')
const app = express()

app.get('/profile', (req, res) => {
  res.render('profile', { profileName: req.body.name })
})
