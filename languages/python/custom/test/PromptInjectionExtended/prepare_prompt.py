def prepare_prompt(retrieved_examples, user_post, prompt_template):
    """Builds the prompt from the template, mixing instructions and the user post."""
    return prompt_template.substitute({"retrieved_examples": retrieved_examples, "user_post": user_post})


def prepare_prompt_safe_substitute(user_post, prompt_template):
    return prompt_template.safe_substitute(user_post=user_post)
