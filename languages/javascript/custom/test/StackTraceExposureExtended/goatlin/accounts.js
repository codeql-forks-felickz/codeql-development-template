const express = require('express')
const Note = require('../models/note')

const router = express.Router()

router.post('/accounts', async (req, res, next) => {
  try {
    await Note.create(req.body)
    res.status(201)
  } catch (e) {
    let status = 404
    let error = 'Failed to create account'

    if (e.name === 'MongoError' && e.code === 11000) {
      status = 409
      error = 'Email address is already registered'
    }

    res.status(status).json({ error })
  } finally {
    res.end()
  }
})

router.get('/accounts/:username/notes', async (req, res, next) => {
  try {
    const notes = await Note.find({ owner: req.params.username }).exec()
    res.status(200).json(notes).end()
  } catch (e) { // $ Source
    let status = 500
    let error = e.message

    console.error(e)

    res.status(status).json({ error }) // $ Alert
  } finally {
    res.end()
  }
})

router.get('/accounts/:username/notes/count', async (req, res, next) => {
  try {
    res.json(await Note.countDocuments({ owner: req.params.username }))
  } catch (e) { // $ Source
    res.status(500).send('Failed to count notes: ' + e.message) // $ Alert
  }
})

router.get('/accounts/:username/notes/latest', async (req, res, next) => {
  try {
    res.json(await Note.findOne({ owner: req.params.username }))
  } catch (e) {
    // String conversion of the whole error is not reported, as in js/stack-trace-exposure.
    res.status(500).send('Failed to load note: ' + e)
  }
})

module.exports = router
