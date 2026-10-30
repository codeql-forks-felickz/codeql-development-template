// Well-formed reduction of a finding whose original file is truncated and fails to parse.
const jsyaml = require('js-yaml');
const express = require('express');

const app = express();

app.post('/store/:data', function (req, res) {
  const unsafeConfig = { schema: jsyaml.DEFAULT_FULL_SCHEMA };
  // BAD: the full schema allows `!!js/function` and other unsafe types
  const data = jsyaml.safeLoad(req.params.data, unsafeConfig);
  // GOOD: default (safe) schema
  const safe = jsyaml.safeLoad(req.params.data);
  res.send([data, safe]);
});
