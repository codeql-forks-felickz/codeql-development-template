import { Model, DataTypes, type Sequelize } from 'sequelize'

class Product extends Model {
  declare id: number
  declare name: string
}

const ProductModelInit = (sequelize: Sequelize) => {
  Product.init(
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      name: DataTypes.STRING
    },
    { tableName: 'Products', sequelize }
  )
}

export { Product as ProductModel, ProductModelInit }
