import { Model, DataTypes, type Sequelize } from 'sequelize'

// A second user-like model declared with `sequelize.define`.
export const AccountModelInit = (sequelize: Sequelize) =>
  sequelize.define('Account', {
    email: DataTypes.STRING,
    isAdmin: { type: DataTypes.BOOLEAN, defaultValue: false }
  })
