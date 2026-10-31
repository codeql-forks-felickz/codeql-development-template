def create_plain(response, session):
    response.set_cookie("vulpy_session", session)
    return response


def create_encrypted(response, session):
    response.set_cookie("vulpy_session", session)
    return response


def create_theme(response, theme):
    response.set_cookie("theme", theme)  # GOOD: unrelated cookie
    return response
