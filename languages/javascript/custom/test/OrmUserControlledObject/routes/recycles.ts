import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

export const getRecycleItem = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id) // $ Alert
    }
  }).then((recycle) => {
    return res.send(recycle)
  })
}

export const findRecycles = () => (req: Request, res: Response) => {
  const filter = JSON.parse(req.query.filter as string) // $ Source
  RecycleModel.findOne({ where: filter }).then((recycle) => { // $ Alert
    return res.send(recycle)
  })
}

export const createRecycle = () => (req: Request, res: Response) => {
  RecycleModel.create(req.body).then((recycle) => { // $ Alert
    return res.send(recycle)
  })
}

export const updateRecycle = () => async (req: Request, res: Response) => {
  const recycle = await RecycleModel.findByPk(req.params.id)
  await recycle.update(req.body) // $ Alert
  res.send(recycle)
}

// Safe: the path parameter stays a string and is bound as a value.
export const getRecycleItemSafe = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: req.params.id
    }
  }).then((recycle) => {
    return res.send(recycle)
  })
}

// Safe: the parsed value is coerced to a number.
export const getRecycleItemParsedNumber = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: Number(JSON.parse(req.params.id))
    }
  }).then((recycle) => {
    return res.send(recycle)
  })
}

// Safe: only allow-listed fields are written.
export const createRecycleSafe = () => (req: Request, res: Response) => {
  RecycleModel.create({ UserId: req.body.UserId, quantity: req.body.quantity }).then((recycle) => {
    return res.send(recycle)
  })
}

export const buildRecycleWithFields = () => (req: Request, res: Response) => {
  RecycleModel.build(req.body, { fields: ['quantity'] }) // $ Alert
  res.end()
}

export const constructRecycleWithFields = () => (req: Request, res: Response) => {
  new RecycleModel(req.body, { fields: ['quantity'] }) // $ Alert
  res.end()
}
