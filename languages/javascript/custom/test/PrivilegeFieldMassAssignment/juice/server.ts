import express, { type Request, type Response } from 'express'
import * as finale from 'finale-rest'
import { Sequelize } from 'sequelize'
import { UserModel } from './models/user'
import { ProductModel } from './models/product'
import { AccountModelInit } from './models/account'

const app = express()
app.use(express.json())
const seq = new Sequelize('sqlite::memory:')
const AccountModel = AccountModelInit(seq)

// Reduced from the juice-shop generated REST API: finale exposes a create
// endpoint for `UserModel` that copies every request body attribute, including
// `role`, into the new record.
finale.initialize({ app, sequelize: seq })

const autoModels = [
  { name: 'User', exclude: ['password', 'totpSecret'], model: UserModel },
  { name: 'Product', exclude: [], model: ProductModel }
]

for (const { name, exclude, model } of autoModels) {
  const resource = finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`], excludeAttributes: exclude }) // $ Alert
  if (name === 'User') {
    resource.create.send.before((req: Request, res: Response, context: any) => context.continue)
  }
}

finale.resource({ model: AccountModel, endpoints: ['/api/Accounts'] }) // $ Alert

// Direct Sequelize creation with a body-supplied role.
app.post('/rest/register', async (req: Request, res: Response) => {
  const user = await UserModel.create({ email: req.body.email, role: req.body.role }) // $ Alert
  res.json(user)
})

// ---------------------------------------------------------------------------
// Safe counterparts: none of these should alert.
// ---------------------------------------------------------------------------

// Model without a privilege field.
finale.resource({ model: ProductModel, endpoints: ['/api/Items'] })

// Read-only endpoints for a model with a privilege field.
finale.resource({ model: UserModel, endpoints: ['/api/ReadOnlyUsers'], actions: ['read', 'list'] })

// Role fixed by the server.
app.post('/rest/register_safe', async (req: Request, res: Response) => {
  const user = await UserModel.create({ email: req.body.email, role: 'customer' })
  res.json(user)
})

app.listen(3000)
