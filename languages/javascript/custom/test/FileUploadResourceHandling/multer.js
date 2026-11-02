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

// GOOD: `.none()` rejects every file.
var textOnly = multer();
textOnly.none();

// BAD: this instance also creates file-accepting middleware.
var mixed = multer(); // $ Alert
mixed.none();
mixed.single('file');

// BAD: an instance that escapes through an argument may be used elsewhere.
var passed = multer(); // $ Alert
passed.none();
consume(passed);

// BAD: an instance that is exported may be used elsewhere.
var exported = multer(); // $ Alert
exported.none();
module.exports = exported;

// GOOD: file type validation and size limit.
var safe = multer({ dest: 'uploads/', limits: { fileSize: 1024 * 1024 }, fileFilter: imageFilter });

// GOOD: options defined separately.
var opts = { dest: 'uploads/', limits: { fileSize: 1024 * 1024 }, fileFilter: imageFilter };
var safe2 = multer(opts);

// GOOD: options are not statically known.
var safe3 = multer(require('./upload-config'));

module.exports = { upload, memoryUpload, noFilter, noSize, safe, safe2, safe3 };
