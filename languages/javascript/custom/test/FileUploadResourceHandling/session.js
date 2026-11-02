var express = require('express');
var session = require('express-session');
var RedisStore = require('connect-redis').default;
var redisClient = require('./redis-client');

var app = express();

// BAD: default in-process MemoryStore with no capacity limit.
app.use(session({
  secret: 'keyboard cat',
  name: 'connect.sid',
  cookie: { path: '/' }
})); // $ Alert

// GOOD: external session store.
app.use(session({
  secret: 'keyboard cat',
  store: new RedisStore({ client: redisClient }),
  cookie: { maxAge: 60 * 60 * 1000 }
}));

// GOOD: options are not statically known.
app.use(session(require('./session-config')));
