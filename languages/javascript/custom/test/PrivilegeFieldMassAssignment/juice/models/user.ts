import { Model, DataTypes, type Sequelize } from 'sequelize'

class User extends Model {
  declare id: number
  declare email: string
  declare role: string
}

const UserModelInit = (sequelize: Sequelize) => {
  User.init(
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      email: { type: DataTypes.STRING, unique: true },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: { isIn: [['customer', 'deluxe', 'accounting', 'admin']] }
      }
    },
    { tableName: 'Users', sequelize }
  )
}

export { User as UserModel, UserModelInit }
