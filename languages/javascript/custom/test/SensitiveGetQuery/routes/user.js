const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const database = require('../utils/database');

// GET login on an Express Router mounted from another file, async handler wrapped in try/catch.
router.get('/login', async function (req, res, next) {
    try {
        const username = req.query.username;
        const password = req.query.password; // $ Alert[js/sensitive-get-query]
        const result = await database.query('SELECT * FROM users WHERE name = ?', [username]);
        const user = result[0][0];
        bcrypt.compare(password, user.password_hash, function (err, ok) {
            if (ok) {
                res.json({ result: 'successfully logged in!' });
            } else {
                res.status(401).json({ message: 'Wrong password!' });
            }
        });
    } catch (err) {
        next(err);
    }
});

// GET register reading the password from the query string.
router.get('/register', async function (req, res) {
    const password = req.query.password; // $ Alert[js/sensitive-get-query]
    bcrypt.hash(password, 10, function (err, hash) {
        res.json({ hash: hash });
    });
});

// Arrow-function handler with destructuring.
router.get('/login-arrow', (req, res) => {
    const { password } = req.query; // $ Alert[js/sensitive-get-query]
    bcrypt.compare(password, 'hash', (err, ok) => res.json({ ok }));
});

// Safe: POST login reads the password from the request body.
router.post('/login', async function (req, res) {
    const password = req.body.password;
    bcrypt.compare(password, 'hash', (err, ok) => res.json({ ok }));
});

// Safe: GET route reading only non-sensitive query parameters.
router.get('/search', function (req, res) {
    const term = req.query.term;
    res.json({ term: term });
});

module.exports = router;
