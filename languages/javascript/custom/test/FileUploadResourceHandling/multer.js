var multer = require('multer');

function imageFilter(req, file, cb) {
  cb(null, file.mimetype === 'image/png' || file.mimetype === 'image/jpeg');
}

// BAD: no file type validation and no size limit.
var upload = multer({ dest: 'uploads/' }); // $ Alert

// BAD: in-memory storage with no file type validation and no size limit.
var memoryUpload = multer(); // $ Alert

// BAD: size limit, but no file type validation.
var noFilter = multer({ dest: 'uploads/', limits: { fileSize: 1024 * 1024 } }); // $ Alert

// BAD: file type validation, but no per-file size limit.
var noSize = multer({ storage: multer.memoryStorage(), limits: { files: 1 }, fileFilter: imageFilter }); // $ Alert

// GOOD: file type validation and size limit.
var safe = multer({ dest: 'uploads/', limits: { fileSize: 1024 * 1024 }, fileFilter: imageFilter });

// GOOD: options defined separately.
var opts = { dest: 'uploads/', limits: { fileSize: 1024 * 1024 }, fileFilter: imageFilter };
var safe2 = multer(opts);

// GOOD: options are not statically known.
var safe3 = multer(require('./upload-config'));

module.exports = { upload, memoryUpload, noFilter, noSize, safe, safe2, safe3 };
