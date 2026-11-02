import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished, pipeline } from 'node:stream/promises'
import { Transform } from 'node:stream'
import express, { type Request, type Response, type NextFunction } from 'express'
import request from 'request'
import https from 'node:https'

const app = express()
const MAX_DOWNLOAD_BYTES = 1024 * 1024

function createByteLimitTransform () {
  let downloadedBytes = 0
  return new Transform({
    transform (chunk, encoding, callback) {
      downloadedBytes += chunk.length
      callback(downloadedBytes > MAX_DOWNLOAD_BYTES ? new Error('download too large') : null, chunk)
    }
  })
}

// BAD: response from a user-selected URL is streamed to disk with no byte limit.
export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const url = req.body.imageUrl
    const response = await fetch(url)
    if (!response.ok || !response.body) {
      throw new Error('url returned a non-OK status code or an empty body')
    }
    const fileStream = fs.createWriteStream('uploads/avatar.jpg', { flags: 'w' })
    await finished(Readable.fromWeb(response.body as any).pipe(fileStream)) // $ Alert
    res.redirect('/profile')
  }
}

// BAD: legacy request client piped straight to disk.
app.post('/profile/image/legacy', (req, res) => {
  request.get(req.body.imageUrl)
    .on('error', () => res.status(500).end())
    .pipe(fs.createWriteStream('uploads/avatar.jpg')) // $ Alert
  res.redirect('/profile')
})

// BAD: Node.js https client response piped straight to disk.
app.post('/profile/image/https', (req, res) => {
  https.get(req.query.url as string, (download) => {
    download.pipe(fs.createWriteStream('uploads/avatar.jpg')) // $ Alert
  })
  res.redirect('/profile')
})

// BAD: response event handler of a Node.js https request.
app.post('/profile/image/https-event', (req, res) => {
  https.request(req.query.url as string).on('response', (download) => {
    pipeline(download, fs.createWriteStream('uploads/avatar.jpg')) // $ Alert
  }).end()
  res.redirect('/profile')
})

// GOOD: a byte-limiting transform sits between the response and file.
app.post('/profile/image/limited', (req, res) => {
  https.get(req.query.url as string, (download) => {
    pipeline(download, createByteLimitTransform(), fs.createWriteStream('uploads/avatar.jpg'))
  })
  res.redirect('/profile')
})

// GOOD: a chained intermediate stream prevents reporting the final pipe.
app.post('/profile/image/limited-pipe', (req, res) => {
  https.get(req.query.url as string, (download) => {
    download.pipe(createByteLimitTransform()).pipe(fs.createWriteStream('uploads/avatar.jpg'))
  })
  res.redirect('/profile')
})

// GOOD: URL is not user-controlled.
app.post('/profile/image/default', async (req, res) => {
  const response = await fetch('https://cdn.example.com/default-avatar.jpg')
  await finished(Readable.fromWeb(response.body as any).pipe(fs.createWriteStream('uploads/avatar.jpg')))
  res.redirect('/profile')
})

// GOOD: user-controlled URL, but the response is not written to a file.
app.post('/profile/image/check', async (req, res) => {
  const response = await fetch(req.body.imageUrl)
  res.json({ ok: response.ok })
})
