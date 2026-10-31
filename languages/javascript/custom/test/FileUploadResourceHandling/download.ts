import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import express, { type Request, type Response, type NextFunction } from 'express'
import request from 'request'

const app = express()

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
