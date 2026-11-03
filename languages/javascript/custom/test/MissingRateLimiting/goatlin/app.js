const express = require('express');
const accountsRouter = require('./routes/accounts');

const app = express();
app.use(express.json());
app.use('/', accountsRouter);

module.exports = app;
