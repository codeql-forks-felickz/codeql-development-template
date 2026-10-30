const express = require('express');
const logger = require('morgan');
const usersRouter = require('./routes/user');

const app = express();
// Request URLs (including query strings) are written to the service log.
app.use(logger(':method :url :status'));
app.use('/user', usersRouter);

module.exports = app;
