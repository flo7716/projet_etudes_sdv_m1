import questionary


def prompt_text(message, default="", validate=None):
    answer = questionary.text(
        message,
        default=default,
        validate=validate,
    ).ask()
    if answer is None:
        raise KeyboardInterrupt("Input cancelled")
    return answer
