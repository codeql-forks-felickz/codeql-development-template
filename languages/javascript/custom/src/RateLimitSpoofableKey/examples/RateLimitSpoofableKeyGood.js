const express = require('express');
const { rateLimit } = require('express-rate-limit');

const app = express();
// Exactly one reverse proxy sits in front of the application.
app.set('trust proxy', 1);

app.use('/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.ip
}));
