// A separate application that does not trust any proxy.
const express = require('express');
const rateLimit = require('express-rate-limit');

const app = express();

// GOOD: `req.ip` is the socket address because this application does not trust proxies.
app.post('/login', rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip
}), (req, res) => res.end());
