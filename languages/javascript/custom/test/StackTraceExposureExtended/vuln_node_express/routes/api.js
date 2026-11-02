const express = require('express')
const router = express.Router()
const searchService = require('../service/search')

router.get('/search', function (req, res, next) {
  const searchText = req.query.searchText !== undefined ? req.query.searchText : ''
  searchService.searchByName(searchText, function (err, ret) { // $ Source
    if (err) {
      res.json(err) // $ Alert
    } else {
      res.json(ret)
    }
  })
})

router.get('/search-safe', function (req, res, next) {
  searchService.searchByName(req.query.searchText, function (err, ret) {
    if (err) {
      console.error(err)
      res.status(500).json({ error: 'Search failed', code: err.code })
    } else {
      res.json(ret)
    }
  })
})

module.exports = router
