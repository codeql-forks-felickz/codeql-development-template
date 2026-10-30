var express = require('express');
var jwt = require('jwt-simple')
var jwtUtil = require('../utils/jwt')
var router = express.Router();

router.post('/logout', async function (req, res) {
    var jwtToken = req.body.jwt;
    let decoded;
    try {
        // BAD: jwt-simple without an algorithm lets the token header choose it
        decoded = jwt.decode(jwtToken, jwtUtil.JwtPublic); // $ Alert
    } catch (ex) {
        return res.sendStatus(401);
    }
    res.json({ result: 'successfully logged out!' })
});

router.post('/isValid', async function (req, res) {
    const jwtToken = req.body.jwt;
    let decoded;
    try {
        // BAD: jwt-simple without an algorithm lets the token header choose it
        decoded = jwt.decode(jwtToken, jwtUtil.JwtPublic) // $ Alert
    } catch (ex) {
        return res.sendStatus(401);
    }
    return res.json({ result: 'token is valid' })
});

router.post('/isValidPinned', async function (req, res) {
    // GOOD: algorithm pinned
    const decoded = jwt.decode(req.body.jwt, jwtUtil.JwtPublic, false, 'RS256');
    return res.json({ result: decoded.username })
});

router.post('/unsafeNoVerify', async function (req, res) {
    // BAD: signature verification explicitly disabled
    const decoded = jwt.decode(req.body.jwt, jwtUtil.JwtPublic, true); // $ Alert
    return res.json({ result: decoded.username })
});

module.exports = router;
