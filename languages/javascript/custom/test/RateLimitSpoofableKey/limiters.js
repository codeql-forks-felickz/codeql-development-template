const express = require('express');
const RateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

const router = express.Router();

router.post('/login', RateLimit({
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.get('X-Real-IP') // $ Alert
}), (req, res) => res.end());

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for']; // $ Source
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
}

const options = {
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: function (req, res) {
    return getClientIp(req); // $ Alert
  }
};
router.post('/forgot-password', new RateLimit(options), (req, res) => res.end());

router.post('/otp', slowDown({
  windowMs: 60 * 1000,
  delayAfter: 3,
  keyGenerator: (req) => req.header('cf-connecting-ip') // $ Alert
}), (req, res) => res.end());

// GOOD: an API key header is not a client address header.
router.post('/api', RateLimit({
  keyGenerator: (req) => req.headers['x-api-key']
}), (req, res) => res.end());

// GOOD: the socket address cannot be spoofed by the client.
router.post('/register', RateLimit({
  keyGenerator: (req) => req.socket.remoteAddress
}), (req, res) => res.end());

module.exports = router;
