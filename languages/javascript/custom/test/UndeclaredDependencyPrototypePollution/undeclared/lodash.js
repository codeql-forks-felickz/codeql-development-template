const express = require('express')
const router = express.Router()

const lodash = require('lodash')

// Reduced from a real-world finding: lodash is used but not declared in any package.json,
// so its version is unknown. `defaultsDeep` before lodash 4.17.12 (CVE-2019-10744) follows
// `constructor.prototype` keys, e.g. '{"constructor": {"prototype": {"isAdmin": true}}}'.
function check(req, res) {
  let config = {}
  lodash.defaultsDeep(config, JSON.parse(req.body.config)) // $ Alert
  res.send('ok')
}

function update(req, res) {
  lodash.merge({}, JSON.parse(req.body.settings)) // $ Alert
  res.send('ok')
}

// Safe: shallow merge, so nested keys are not followed.
function shallow(req, res) {
  lodash.defaults({}, JSON.parse(req.body.config))
  res.send('ok')
}

// Safe: constant data.
function constant(req, res) {
  lodash.defaultsDeep({}, { theme: 'dark' })
  res.send('ok')
}

router.post('/check-user', check)
router.post('/update', update)
router.post('/shallow', shallow)
router.post('/constant', constant)

module.exports = router
