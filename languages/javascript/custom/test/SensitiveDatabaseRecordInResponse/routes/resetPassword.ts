import { type Request, type Response } from "express";
import { UserModel, MemberModel } from "../models/user";

// Reduced from juice-shop: a password reset returns the whole updated user.
export function resetPassword() {
  return async ({ body }: Request, res: Response) => {
    const user = await UserModel.findByPk(body.id);
    if (user) {
      const updatedUser = await user.update({ password: body.new }); // $ Source
      res.json({ user: updatedUser }); // $ Alert
    }
  };
}

export function profile() {
  return async ({ body }: Request, res: Response) => {
    const user = await UserModel.findOne({ where: { email: body.email } }); // $ Source
    res.json(user); // $ Alert

    // Safe: only non-sensitive fields are returned.
    res.json({ id: user?.id, email: user?.email });

    // Safe: only the selected attributes are loaded.
    const named = await UserModel.findOne({ attributes: ["id", "email"] });
    res.json(named);

    // Safe: the password is masked when the record is copied.
    const users = await UserModel.findAll();
    res.json({
      data: users.map((u) => ({ ...u.dataValues, password: "********" }))
    });

    res.json({ password: "********", ...user.dataValues }); // $ Alert
    res.json({ ...user.dataValues, password: user.password }); // $ Alert

    // Safe: the model's `toJSON` removes the password.
    const member = await MemberModel.findByPk(body.id);
    res.json(member);
  };
}
