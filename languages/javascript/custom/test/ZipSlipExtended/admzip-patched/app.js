const express = require('express');
const fileUpload = require('express-fileupload');
const AdmZip = require('adm-zip');

const app = express();
app.use(fileUpload());

// GOOD: adm-zip >= 0.4.11 sanitizes entry names in `extractAllTo`.
app.post('/import', function (req, res) {
  const zip = new AdmZip(req.files.importFile.data);
  zip.extractAllTo('/tmp/extracted_files', true);
  res.send('ok');
});

module.exports = { app };
