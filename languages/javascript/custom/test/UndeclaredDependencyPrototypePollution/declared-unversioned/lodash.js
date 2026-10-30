const express = require('express')
const router = express.Router()
const lodash = require('lodash')

// Not reported by this query: lodash is declared, so the stock `js/prototype-pollution`
// query decides based on the declared version.
router.post('/check-user', (req, res) => {
  lodash.defaultsDeep({}, JSON.parse(req.body.config))
  res.send('ok')
})

module.exports = router
