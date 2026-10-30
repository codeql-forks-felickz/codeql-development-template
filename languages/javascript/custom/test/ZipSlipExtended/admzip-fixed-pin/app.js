const AdmZip = require('adm-zip');

// GOOD: adm-zip 0.4.11 is the first release that sanitizes entry names.
function extractLocal(file) {
  AdmZip(file).extractAllTo('/tmp/out');
}

module.exports = { extractLocal };
