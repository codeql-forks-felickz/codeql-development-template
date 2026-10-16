import os
import tempfile

from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)  # $ Source

with open("/tmp/ca.key", "wb") as out:
    out.write(pem_private)  # $ Alert

with open(os.path.join(tempfile.gettempdir(), "server.key"), "wb") as f:
    f.write(pem_private)  # $ Alert

pkey = crypto.PKey()
pkey.generate_key(crypto.TYPE_RSA, 2048)
with open("/var/tmp/service.pem", "w") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode())  # $ Alert


# --- Safe cases ---

# Safe: pyOpenSSL key protected with a cipher and passphrase.
with open("/var/tmp/service-encrypted.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey, "aes256", os.environ["PASS"].encode()))

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Safe: public key material.
with open("/tmp/ca.pub", "wb") as out:
    out.write(pem_public)

# Safe: private key is encrypted with a passphrase.
pem_encrypted = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(os.environ["KEY_PASSPHRASE"].encode()),
)
with open("/tmp/ca-encrypted.key", "wb") as out:
    out.write(pem_encrypted)

# Safe for this query: not a shared, predictable temporary location.
with open("ca.key", "wb") as out:
    out.write(pem_private)

# Safe: unique file created with mkstemp (O_EXCL, mode 0600).
fd, path = tempfile.mkstemp(suffix=".key")
with os.fdopen(fd, "wb") as out:
    out.write(pem_private)
