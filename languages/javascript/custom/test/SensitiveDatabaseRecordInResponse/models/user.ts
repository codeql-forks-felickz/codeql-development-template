import { Model, DataTypes, type Sequelize } from "sequelize";

// Reduced from juice-shop: the password setter hashes the value, but the hash and the
// TOTP secret are still part of every serialized record.
class User extends Model {
  declare id: number;
  declare email: string;
  declare password: string;
  declare totpSecret: string;
}

const UserModelInit = (sequelize: Sequelize, hash: (v: string) => string) => {
  User.init(
    {
      id: { type: DataTypes.INTEGER, primaryKey: true },
      email: DataTypes.STRING,
      password: {
        type: DataTypes.STRING,
        set(clearTextPassword: string) {
          this.setDataValue("password", hash(clearTextPassword));
        }
      },
      totpSecret: { type: DataTypes.STRING, defaultValue: "" }
    },
    { tableName: "Users", sequelize }
  );
};

// Safe: `toJSON` removes the password before records are serialized.
class Member extends Model {
  declare password: string;

  toJSON() {
    const values: any = { ...this.get() };
    delete values.password;
    return values;
  }
}

const MemberModelInit = (sequelize: Sequelize) => {
  Member.init({ email: DataTypes.STRING, password: DataTypes.STRING }, { sequelize });
};

export { User as UserModel, UserModelInit, Member as MemberModel, MemberModelInit };
