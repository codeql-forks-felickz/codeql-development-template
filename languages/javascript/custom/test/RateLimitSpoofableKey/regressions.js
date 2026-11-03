const express = require('express');
const rateLimit = require('express-rate-limit');

const unmountedRouter = express.Router();
unmountedRouter.post('/orphan', rateLimit({
  keyGenerator: (req) => req.ip // $ Alert
}), (req, res) => res.end());
module.exports = unmountedRouter;

const unrelatedTrustedApp = express();
unrelatedTrustedApp.enable('trust proxy');

const trustingParent = express();
trustingParent.enable('trust proxy');

const fixedHopSubApp = express();
fixedHopSubApp.set('trust proxy', 1);
fixedHopSubApp.post('/fixed-hop', rateLimit({
  keyGenerator: (req) => req.ip
}), (req, res) => res.end());
trustingParent.use('/fixed-hop', fixedHopSubApp);

const disabledSubApp = express();
disabledSubApp.disable('trust proxy');
disabledSubApp.post('/disabled', rateLimit({
  keyGenerator: (req) => req.ip
}), (req, res) => res.end());
trustingParent.use('/disabled', disabledSubApp);

const nonTrustingParent = express();
const enabledSubApp = express();
enabledSubApp.enable('trust proxy');
enabledSubApp.post('/enabled', rateLimit({
  keyGenerator: (req) => req.ip // $ Alert
}), (req, res) => res.end());
nonTrustingParent.use('/enabled', enabledSubApp);

const setTrustingSubApp = express();
setTrustingSubApp.set('trust proxy', true);
setTrustingSubApp.post('/set-trusting', rateLimit({
  keyGenerator: (req) => req.ip // $ Alert
}), (req, res) => res.end());
nonTrustingParent.use('/set-trusting', setTrustingSubApp);

const sharedKeyGenerator = (req) => req.ip; // $ Alert
const sharedTrustedApp = express();
sharedTrustedApp.enable('trust proxy');
sharedTrustedApp.post('/shared-key', rateLimit({
  keyGenerator: sharedKeyGenerator
}), (req, res) => res.end());
const sharedSafeApp = express();
sharedSafeApp.post('/shared-key', rateLimit({
  keyGenerator: sharedKeyGenerator
}), (req, res) => res.end());

function readClientIp(req) {
  return req.ip; // $ Source
}

const sharedHelperTrustedApp = express();
sharedHelperTrustedApp.enable('trust proxy');
sharedHelperTrustedApp.post('/shared-helper', rateLimit({
  keyGenerator: (req) => readClientIp(req) // $ Alert
}), (req, res) => res.end());
const sharedHelperSafeApp = express();
sharedHelperSafeApp.post('/shared-helper', rateLimit({
  keyGenerator: (req) => readClientIp(req)
}), (req, res) => res.end());
