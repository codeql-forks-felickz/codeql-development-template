import fs from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import unzipper from 'unzipper'

// BAD: ES module default import of `unzipper` with TypeScript type annotations.
export async function extractZipBuffer (buffer: Buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  for (const entry of directory.files) {
    const fileName = entry.path // $ Alert
    const absolutePath = path.resolve('uploads/complaints/' + fileName)
    if (absolutePath.includes(path.resolve('.'))) {
      await pipeline(entry.stream(), fs.createWriteStream('uploads/complaints/' + fileName)) // $ Sink
    }
  }
}
