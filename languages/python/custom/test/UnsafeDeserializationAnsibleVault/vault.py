import sys

import yaml
from ansible.parsing.vault import VaultLib
from flask import Flask, request  # $ Source[py/unsafe-deserialization]

app = Flask(__name__)


class Vault(object):
    '''R/W an ansible-vault yaml file'''

    def __init__(self, password):
        self.password = password
        self.vault = VaultLib(password)

    def load(self, stream):
        '''read vault stream and return python object'''
        return yaml.load(self.vault.decrypt(stream))[0]  # $ Alert[py/unsafe-deserialization]

    def load_safe(self, stream):
        # Safe: SafeLoader only constructs plain Python types.
        return yaml.load(self.vault.decrypt(stream), Loader=yaml.SafeLoader)[0]


@app.route("/vault", methods=["POST"])
def load_uploaded_vault():
    return str(Vault("secret").load(request.data))


@app.route("/vault-id", methods=["POST"])
def load_uploaded_vault_with_id():
    plaintext, _, _ = VaultLib("secret").decrypt_and_get_vault_id(request.data)
    return str(yaml.unsafe_load(plaintext))  # $ Alert[py/unsafe-deserialization]


@app.route("/vault-safe", methods=["POST"])
def load_uploaded_vault_safe():
    return str(Vault("secret").load_safe(request.data))


def cli():
    with open(sys.argv[1]) as f:  # $ Source[py/unsafe-deserialization]
        return Vault("secret").load(f.read())
