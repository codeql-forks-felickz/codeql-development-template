import { Model, DataTypes, type Sequelize } from 'sequelize'

class User extends Model {
  declare id: number
  declare username: string
}

const UserModelInit = (sequelize: Sequelize) => {
  User.init({ username: { type: DataTypes.STRING } }, { tableName: 'Users', sequelize })
}

export { User as UserModel, UserModelInit }
