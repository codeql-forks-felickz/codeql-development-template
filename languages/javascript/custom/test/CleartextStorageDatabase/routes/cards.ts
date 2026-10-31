import express from "express";
import { CardModel, TokenizedCard, Member } from "../models/card";

const router = express.Router();

// Reduced from juice-shop: seeding a card persists the clear-text card number.
export async function createCard(UserId: number, card: { fullName: string; cardNum: string }) {
    return await CardModel.create({
        UserId,
        fullName: card.fullName,
        cardNum: Number(card.cardNum) // $ Alert
    });
}

router.post("/cards", async (req, res) => {
    await CardModel.create(req.body); // $ Alert
    res.status(201).end();
});

// Safe: the model encrypts `cardNum` in a setter.
router.post("/tokenized-cards", async (req, res) => {
    await TokenizedCard.create(req.body);
    await TokenizedCard.create({ cardNum: req.body.cardNum });
    res.status(201).end();
});

// Safe: the model hashes passwords in a `beforeSave` hook.
router.post("/members", async (req, res) => {
    await Member.create(req.body);
    res.status(201).end();
});

export default router;
