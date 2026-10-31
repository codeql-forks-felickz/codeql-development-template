const swig = require('swig')
const express = require('express')
const { MongoClient } = require('mongodb')
const app = express()
const db = new MongoClient('mongodb://localhost').db()

swig.setDefaults({ autoescape: false })

app.get('/profile', (req, res) => {
  res.render('profile', {
    profileName: req.body.name,
    title: 'Profile'
  })
})

app.get('/stored-profile', async (req, res) => {
  const profile = await db.collection('profiles').findOne({ _id: req.params.id })
  res.render('profile', {
    profileName: profile.firstName,
    title: 'Profile'
  })
})
