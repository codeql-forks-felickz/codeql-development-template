// The application only trusts the first proxy hop, so `req.ip` is the address seen by that
// proxy and cannot be chosen by the client.
const express = require('express');
const { rateLimit } = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);

// GOOD: `req.ip` is not spoofable when only a fixed number of proxy hops is trusted.
app.use('/login', rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.ip
}));

// BAD: the raw header is still client-controlled.
app.use('/reset', rateLimit({
  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip // $ Alert
}));

// GOOD: Node.js lower-cases header names, so `req.headers['X-Real-IP']` is always undefined
// and the key is `req.ip`.
app.use('/verify', rateLimit({
  keyGenerator: (req) => req.headers['X-Real-IP'] || req.ip
}));
