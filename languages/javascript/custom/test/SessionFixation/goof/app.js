var express = require('express');
var session = require('express-session');
var routes = require('./routes');

var app = express();
app.use(session({ secret: 'keyboard cat' }));
app.post('/login', routes.loginHandler); // $ Alert
app.post('/safe-login', routes.safeLoginHandler);
app.get('/logout', routes.logout);
