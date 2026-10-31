const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'keyboard cat' }));

function markLoggedIn(session, username) {
    session.username = username;
    session.authenticated = true;
}

app.post('/login', function (req, res) {
    // Check that username password matches
    if (req.body.username === 'admin' && req.body.password === 'admin') {
        markLoggedIn(req.session, req.body.username);
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});
