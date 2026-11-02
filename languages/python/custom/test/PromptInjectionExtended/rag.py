from llama_index.core.llms import ChatMessage

from config import PROMPT_TEMPLATE
from init_models import init_ollama_models, init_openai_models
from prepare_prompt import prepare_prompt, prepare_prompt_safe_substitute


class RAGSpamClassifier:
    def __init__(self, provider):
        if provider == "ollama":
            self._llm_model, self._embeddings_model = init_ollama_models("llama3")
        else:
            self._llm_model, self._embeddings_model = init_openai_models("gpt-4o")

    def classify_text(self, user_post):
        final_prompt = prepare_prompt(
            retrieved_examples="",
            user_post=user_post,
            prompt_template=PROMPT_TEMPLATE,
        )
        llm_response = self._llm_model.complete(final_prompt)  # $ Alert
        return llm_response.text.strip().lower()

    async def classify_text_async(self, user_post):
        prompt = prepare_prompt_safe_substitute(user_post, PROMPT_TEMPLATE)
        return await self._llm_model.acomplete(prompt=prompt)  # $ Alert

    def classify_text_fstring(self, user_post):
        return self._llm_model.stream_complete(f"Classify as spam or not_spam: {user_post}")  # $ Alert

    def classify_text_chat(self, user_post):
        # Safe: the instructions and the untrusted post are kept in separate messages.
        messages = [
            ChatMessage(role="system", content="Classify the user message as spam or not_spam."),
            ChatMessage(role="user", content=user_post),
        ]
        return self._llm_model.chat(messages)

    def classify_constant(self, user_post):
        # Safe: the prompt does not contain the untrusted post.
        if user_post:
            return self._llm_model.complete("Say hello")


rag_classifier = RAGSpamClassifier("ollama")
