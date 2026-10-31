const express = require('express');
const rateLimit = require('express-rate-limit');
const auth = require('../middleware/auth');

const router = express.Router();

router.get('/accounts/:username/profile', auth, (req, res) => { // $ Alert
  res.json({ username: req.params.username });
});

// GOOD: the authentication middleware is rate-limited.
router.get('/accounts/:username/settings', rateLimit({ windowMs: 60 * 1000, max: 10 }), auth, (req, res) => {
  res.json({ username: req.params.username });
});

module.exports = router;
