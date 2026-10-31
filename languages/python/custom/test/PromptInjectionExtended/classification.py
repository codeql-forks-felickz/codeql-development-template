from fastapi import APIRouter
from pydantic import BaseModel

from rag import rag_classifier

router = APIRouter()


class TextPost(BaseModel):
    text: str


@router.post("/classifyPost")
async def classify_text(post: TextPost):  # $ Source
    return {"classification": rag_classifier.classify_text(post.text)}


@router.post("/classifyPostAsync")
async def classify_text_async(post: TextPost):  # $ Source
    return {"classification": await rag_classifier.classify_text_async(post.text)}


@router.post("/classifyPostFString")
async def classify_text_fstring(post: TextPost):  # $ Source
    return {"classification": rag_classifier.classify_text_fstring(post.text)}


@router.post("/classifyPostChat")
async def classify_text_chat(post: TextPost):
    return {"classification": rag_classifier.classify_text_chat(post.text)}


@router.post("/classifyConstant")
async def classify_constant(post: TextPost):
    return {"classification": rag_classifier.classify_constant(post.text)}
