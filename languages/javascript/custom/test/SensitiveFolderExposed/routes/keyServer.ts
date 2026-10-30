import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      res.sendFile(path.resolve('encryptionkeys/', file)) // NOT OK
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    res.sendFile(path.resolve('ftp/', params.file)) // OK: not sensitive by name
  }
}

export function serveCertFile () {
  return (req: Request, res: Response) => {
    res.sendFile(path.resolve('ssl', 'server.pem')) // OK: a single fixed file, not a whole folder
  }
}

export function downloadKey () {
  return (req: Request, res: Response) => {
    res.download(req.query.name as string, { root: 'private-keys' }) // NOT OK
  }
}
