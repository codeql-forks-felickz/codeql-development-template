const express = require('express');
const session = require('client-sessions');

const app = express();

// BAD: authenticated session cookie explicitly readable from client-side JavaScript.
app.use(session({
  cookieName: 'session',
  secret: process.env.SESSION_SECRET,
  duration: 24 * 60 * 60 * 1000,
  cookie: {
    httpOnly: false,
    maxAge: 1000 * 60 * 150,
  },
})); // $ Alert

// BAD: `httpOnly: false` set through a separately declared options object.
const cookieOptions = { httpOnly: false, secure: true, sameSite: 'strict' };
app.use(session({
  cookieName: 'admin',
  secret: process.env.SESSION_SECRET,
  cookie: cookieOptions,
})); // $ Alert

// GOOD: `httpOnly` defaults to `true` in client-sessions.
app.use(session({
  cookieName: 'session2',
  secret: process.env.SESSION_SECRET,
}));

// GOOD: `httpOnly` defaults to `true` when `cookie` omits it.
app.use(session({
  cookieName: 'session3',
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true },
}));

// GOOD: `httpOnly` explicitly enabled.
app.use(session({
  cookieName: 'session4',
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
}));

// GOOD: top-level `httpOnly` is not a client-sessions cookie option.
app.use(session({
  cookieName: 'session5',
  secret: process.env.SESSION_SECRET,
  httpOnly: false,
}));

module.exports = app;
