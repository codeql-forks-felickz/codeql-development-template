const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');
const unzipper = require('unzipper');

// BAD: substring containment check on a different value is not a traversal barrier.
async function extractWithSubstringCheck(buffer) {
  const directory = await unzipper.Open.buffer(buffer);
  for (const entry of directory.files) {
    const fileName = entry.path; // $ Alert
    const absolutePath = path.resolve('uploads/complaints/' + fileName);
    if (absolutePath.includes(path.resolve('.'))) {
      await pipeline(entry.stream(), fs.createWriteStream('uploads/complaints/' + fileName)); // $ Sink
    }
  }
}

// BAD: directory opened from a file, entries iterated with forEach.
async function extractFromFile(zipPath, dest) {
  const directory = await unzipper.Open.file(zipPath);
  directory.files.forEach((entry) => {
    entry.stream().pipe(fs.createWriteStream(path.join(dest, entry.path))); // $ Alert
  });
}

// GOOD: resolved destination is checked to stay inside the extraction directory.
async function extractSafely(buffer, dest) {
  const directory = await unzipper.Open.buffer(buffer);
  const root = path.resolve(dest);
  for (const entry of directory.files) {
    const target = path.resolve(root, entry.path);
    if (target.startsWith(root + path.sep)) {
      await pipeline(entry.stream(), fs.createWriteStream(target));
    }
  }
}

// GOOD: entry path is reduced to its base name.
async function extractBasename(buffer, dest) {
  const directory = await unzipper.Open.buffer(buffer);
  for (const entry of directory.files) {
    await pipeline(entry.stream(), fs.createWriteStream(path.join(dest, path.basename(entry.path))));
  }
}

module.exports = { extractWithSubstringCheck, extractFromFile, extractSafely, extractBasename };
