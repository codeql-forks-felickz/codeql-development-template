import express, { type Request, type Response, type NextFunction } from 'express'
import serveIndex from 'serve-index'
import serveStatic from 'serve-static'
import path from 'node:path'
import { serveKeyFiles, servePublicFiles, serveCertFile } from './routes/keyServer'

const app = express()

const serveIndexMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const origUrl = req.originalUrl
  if (!origUrl.endsWith('/')) {
    res.redirect(origUrl + '/')
  } else {
    next()
  }
}

/* key folder: directory listing and per-file download */
app.use('/encryptionkeys', serveIndexMiddleware, serveIndex('encryptionkeys', { icons: true, view: 'details' })) // NOT OK
app.use('/encryptionkeys/:file', serveKeyFiles())

/* public download folder: not sensitive by name */
app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // OK
app.use('/ftp/:file', servePublicFiles())

app.use('/secrets', express.static(path.join(__dirname, 'config', 'secrets'))) // NOT OK
app.use(serveStatic('./certs')) // NOT OK
app.use('/assets', express.static('assets')) // OK
app.use('/keyboard', express.static('keyboard-layouts')) // OK: `key` is only part of a word

app.get('/cert', serveCertFile())

app.listen(3000)
