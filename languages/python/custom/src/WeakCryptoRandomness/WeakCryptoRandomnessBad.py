import hashlib
import random


def keygen():
    # BAD: Mersenne Twister output is predictable
    return hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()
