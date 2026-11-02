import { Model, DataTypes, type Sequelize } from 'sequelize'

class Recycle extends Model {
  declare id: number
  declare UserId: number
  declare quantity: number
}

const RecycleModelInit = (sequelize: Sequelize) => {
  Recycle.init(
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      UserId: { type: DataTypes.INTEGER },
      quantity: DataTypes.INTEGER
    },
    { tableName: 'Recycles', sequelize }
  )
}

export { Recycle as RecycleModel, RecycleModelInit }
