require('./mongoose-db');

var express = require('express');
var rateLimit = require('express-rate-limit');
var routes = require('./routes');

var app = express();
app.get('/login', routes.login);
app.post('/login', routes.loginHandler); // $ Alert

// GOOD: the login handler is rate-limited.
var loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.post('/limited-login', loginLimiter, routes.loginHandler);
