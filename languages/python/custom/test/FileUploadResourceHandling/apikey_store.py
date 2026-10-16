# Reduced from an API key store that persists keys as files in /tmp (CWE-377).
import hashlib
import os
import random
import tempfile
from pathlib import Path


def keygen(username):
    key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()
    keyfile = '/tmp/vulpy.apikey.{}.{}'.format(username, key)
    Path(keyfile).touch()  # $ Alert[py/file-upload-resource-handling]
    return key


def authenticate(request):
    key = request.headers['X-APIKEY']
    for f in Path('/tmp/').glob('vulpy.apikey.*.' + key):  # $ Alert[py/file-upload-resource-handling]
        return f.name.split('.')[2]
    return None


def save_upload(filename, data):
    with open("/tmp/upload_" + filename, "wb") as f:  # $ Alert[py/file-upload-resource-handling]
        f.write(data)


def save_upload_fstring(filename, data):
    path = f"/var/tmp/{filename}.bin"
    Path(path).write_bytes(data)  # $ Alert[py/file-upload-resource-handling]


def save_upload_join(filename, data):
    fd = os.open(os.path.join("/tmp", filename), os.O_WRONLY | os.O_CREAT)  # $ Alert[py/file-upload-resource-handling]
    os.write(fd, data)


# Safe: tempfile creates an unpredictable, owner-only file.
def save_upload_safe(data):
    fd, path = tempfile.mkstemp(prefix="upload_")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def save_upload_tempdir_safe(filename, data):
    with tempfile.TemporaryDirectory() as d:
        Path(d, filename).write_bytes(data)


# Safe: application-owned directory, not a shared world-writable one.
def save_upload_app_dir(filename, data):
    with open("/srv/app/uploads/" + filename, "wb") as f:
        f.write(data)


# Safe: a path that merely starts with "/tmpfoo" is not the shared /tmp dir.
def not_tmp(data):
    with open("/tmpdata/report.txt", "wb") as f:
        f.write(data)


# Safe: inspecting the shared directory itself does not use a predictable entry name.
def tmp_is_available():
    return Path("/tmp").is_dir() and os.path.exists("/tmp/")
