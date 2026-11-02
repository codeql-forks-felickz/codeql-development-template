from string import Template

PROMPT_TEMPLATE = Template(
    "You are a spam classifier. Answer only with 'spam' or 'not_spam'.\n"
    "Examples:\n$retrieved_examples\n"
    "Post: $user_post\n"
)
