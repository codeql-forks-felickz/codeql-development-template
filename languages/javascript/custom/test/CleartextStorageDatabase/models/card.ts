import { Model, DataTypes, type Sequelize } from "sequelize";

// Reduced from juice-shop: the card model stores the full card number as is.
class Card extends Model {
    declare UserId: number;
    declare fullName: string;
    declare cardNum: number;
}

const CardModelInit = (sequelize: Sequelize) => {
    Card.init(
        {
            UserId: { type: DataTypes.INTEGER },
            fullName: DataTypes.STRING,
            cardNum: { type: DataTypes.INTEGER }
        },
        { tableName: "Cards", sequelize }
    );
};

// Safe: the card number is encrypted by an attribute setter.
class TokenizedCard extends Model {}

const TokenizedCardInit = (sequelize: Sequelize, encrypt: (v: string) => string) => {
    TokenizedCard.init(
        {
            cardNum: {
                type: DataTypes.STRING,
                set(value: string) {
                    this.setDataValue("cardNum", encrypt(value));
                }
            }
        },
        { sequelize }
    );
};

// Safe: a `beforeSave` hook may hash the password.
class Member extends Model {}

const MemberInit = (sequelize: Sequelize) => {
    Member.init({ email: DataTypes.STRING, password: DataTypes.STRING }, { sequelize });
    Member.beforeSave(async (member: any) => {
        member.password = await hashPassword(member.password);
    });
};

declare function hashPassword(p: string): Promise<string>;

export { Card as CardModel, CardModelInit, TokenizedCard, TokenizedCardInit, Member, MemberInit };
