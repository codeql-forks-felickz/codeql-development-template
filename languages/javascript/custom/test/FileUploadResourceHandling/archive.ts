import fs from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import unzipper from 'unzipper'

const MAX_ENTRY_SIZE = 1024 * 1024

// BAD: every entry is expanded to disk with no limit on expanded size.
export async function extractZipBuffer (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer) // $ Alert
  for (const entry of directory.files) {
    const fileName = entry.path
    const absolutePath = path.resolve('uploads/complaints/' + fileName)
    if (absolutePath.includes(path.resolve('.'))) {
      await pipeline(entry.stream(), fs.createWriteStream('uploads/complaints/' + fileName))
    }
  }
}

// GOOD: expanded entry size is checked before extraction.
export async function extractZipBufferBounded (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  for (const entry of directory.files) {
    if (entry.uncompressedSize > MAX_ENTRY_SIZE) {
      continue
    }
    await pipeline(entry.stream(), fs.createWriteStream('uploads/complaints/' + path.basename(entry.path)))
  }
}

// BAD: streaming parser writes every entry with no expansion limit.
export function extractStream (tempFile: string) {
  fs.createReadStream(tempFile)
    .pipe(unzipper.Parse()) // $ Alert
    .on('entry', function (entry: any) {
      entry.pipe(fs.createWriteStream('uploads/complaints/' + path.basename(entry.path)))
    })
}

// GOOD: streaming parser checks the expanded size of each entry.
export function extractStreamBounded (tempFile: string) {
  fs.createReadStream(tempFile)
    .pipe(unzipper.Parse())
    .on('entry', function (entry: any) {
      if (entry.vars.uncompressedSize > MAX_ENTRY_SIZE) {
        entry.autodrain()
        return
      }
      entry.pipe(fs.createWriteStream('uploads/complaints/' + path.basename(entry.path)))
    })
}

// GOOD: entries are only inspected, never expanded.
export async function listEntries (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  return directory.files.map((entry) => entry.path)
}

// BAD: whole archive is extracted with no expansion limit.
export function extractAll (tempFile: string) {
  fs.createReadStream(tempFile).pipe(unzipper.Extract({ path: 'uploads/complaints' })) // $ Alert
}
