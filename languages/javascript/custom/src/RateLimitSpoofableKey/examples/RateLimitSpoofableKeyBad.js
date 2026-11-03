const express = require('express');
const { rateLimit } = require('express-rate-limit');

const app = express();
app.enable('trust proxy');

app.use('/reset-password', rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip
}));
