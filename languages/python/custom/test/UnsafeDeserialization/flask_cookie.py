import pickle
from base64 import b64decode as b64d
from cStringIO import StringIO
import StringIO as PyStringIO

from flask import Flask, request

app = Flask(__name__)


def loads(strs):
    files = StringIO(strs)
    unpkler = pickle.Unpickler(files)
    return unpkler.load()


@app.route("/")
def home():
    cookie = request.cookies.get("location")
    (digest, location) = cookie.split("!")
    # NON_COMPLIANT: cookie value unpickled through a Python 2 `cStringIO.StringIO` wrapper
    return str(loads(b64d(location)))


@app.route("/pystringio")
def pystringio():
    data = request.cookies.get("data")
    # NON_COMPLIANT: cookie value unpickled through a Python 2 `StringIO.StringIO` wrapper
    return str(pickle.Unpickler(PyStringIO.StringIO(b64d(data))).load())


@app.route("/safe")
def safe():
    # COMPLIANT: constant input
    return str(pickle.Unpickler(StringIO("constant")).load())
