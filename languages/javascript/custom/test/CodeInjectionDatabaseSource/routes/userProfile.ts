import { UserModel } from '../models/user'

export async function renderUsername (id: number) {
  const user = await UserModel.findByPk(id)
  let username = user?.username
  if (username?.match(/#{(.*)}/) !== null) {
    const code = username?.substring(2, username.length - 1)
    username = eval(code) // BAD
  }
  return username
}

export async function renderTemplate (id: number) {
  const user = await UserModel.findOne({ where: { id } })
  return eval('`' + user.username + '`') // BAD
}

export async function renderAll () {
  const users = await UserModel.findAll()
  for (const user of users) {
    eval(user.username) // BAD
  }
}

export function notFromDatabase (username: string) {
  return eval('`' + 'static' + '`') // GOOD - constant
}
