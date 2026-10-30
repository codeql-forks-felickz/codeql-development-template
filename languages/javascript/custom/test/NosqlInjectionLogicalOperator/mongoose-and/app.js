const express = require('express');
const bodyParser = require('body-parser');
const db = require('./db');

const server = express();
server.use(bodyParser.json());

server.post('/login', async (request, response) => {
  const email = request.body.email; // $ Source
  const password = request.body.password; // $ Source
  const user = await db.login({ email, password });
  response.send(String(user));
});

server.post('/safe-login', async (request, response) => {
  const email = request.body.email;
  const password = request.body.password;
  const user = await db.safeLogin({ email, password });
  response.send(String(user));
});

server.post('/register', async (request, response) => {
  const email = request.body.email;
  const password = request.body.password;
  const user = await db.register({ email, password });
  response.send(String(!!user));
});

server.listen(10001);
