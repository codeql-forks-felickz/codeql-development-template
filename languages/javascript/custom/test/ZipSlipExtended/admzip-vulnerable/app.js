const express = require('express');
const fileUpload = require('express-fileupload');
const AdmZip = require('adm-zip');

const app = express();
app.use(fileUpload());

// BAD: adm-zip < 0.4.11 does not sanitize entry names in `extractAllTo`.
app.post('/import', function (req, res) {
  const importFile = req.files.importFile;
  const zip = AdmZip(importFile.data); // $ Alert
  zip.extractAllTo('/tmp/extracted_files', true); // $ Sink
  res.send('ok');
});

// BAD: same issue when the archive is constructed with `new`.
app.post('/import2', function (req, res) {
  const zip = new AdmZip(req.files.archive.data); // $ Alert
  zip.extractEntryTo('docs/', '/tmp/docs', true, true); // $ Sink
  res.send('ok');
});

// BAD: archive read from disk is still attacker-controlled content.
function extractLocal(file) {
  new AdmZip(file).extractAllTo('/tmp/out'); // $ Alert
}

module.exports = { app, extractLocal };
