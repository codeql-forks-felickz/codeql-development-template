# Pre-existing behavior of py/hardcoded-credentials is preserved.
def connect(db):
    return db.connect(user="admin", password="myPa55wordLiteral")  # $ Alert


def check(password):
    # GOOD: short literal compared to a password is still not reported
    return password == "abc"
