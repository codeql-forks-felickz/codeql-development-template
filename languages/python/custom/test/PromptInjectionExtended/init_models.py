from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.llms.ollama import Ollama
from llama_index.llms.openai import OpenAI


def init_ollama_llm(model):
    return Ollama(model=model, request_timeout=120.0)


def init_ollama_models(model):
    return init_ollama_llm(model), OllamaEmbedding(model_name=model)


def init_openai_models(model):
    return OpenAI(model=model), None
