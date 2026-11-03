// HTTP Basic authentication middleware that checks the decoded credentials against the
// database on every request (reduced from a Goatlin-style API service).
const Account = require('../models/account');

module.exports = async function (req, res, next) {
  const header = req.get('Authorization') || '';
  if (header === '') {
    return res.status(401).end();
  }
  const [scheme, data] = header.split(' ');
  const [email, password] = Buffer.from(data, 'base64').toString().split(':');
  const account = await Account.findOne({ email, password }).exec();
  if (account === null) {
    return res.status(401).end();
  }
  return next();
};
