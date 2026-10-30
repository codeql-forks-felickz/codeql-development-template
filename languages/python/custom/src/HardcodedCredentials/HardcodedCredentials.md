# Hard-coded credentials
Including unencrypted hard-coded inbound or outbound authentication credentials within source code or configuration files is dangerous because the credentials may be easily discovered.

Source or configuration files containing hard-coded credentials may be visible to an attacker. For example, the source code may be open source, or it may be leaked or accidentally revealed.

Web framework signing secrets are credentials too. A hard-coded Flask `secret_key` / `SECRET_KEY`, Django `SECRET_KEY`, SimpleJWT `SIGNING_KEY` or PyJWT signing key allows anyone with access to the source code to forge session cookies, signed values and authentication tokens. Because these values are secrets regardless of their length or shape, any non-empty string literal that reaches one of these settings is reported, unless the same setting is also read from the environment (for example `os.environ`, `os.getenv`, `environ.Env` or `decouple.config`) in the same file, or the file is in a test location.

For inbound authentication, hard-coded credentials may allow unauthorized access to the system. This is particularly problematic if the credential is hard-coded in the source code, because it cannot be disabled easily. For outbound authentication, the hard-coded credentials may provide an attacker with privileged information or unauthorized access to some other system.


## Recommendation
Remove hard-coded credentials, such as user names, passwords and certificates, from source code, placing them in configuration files or other data stores if necessary. If possible, store configuration files including credential data separately from the source code, in a secure location with restricted access.

For outbound authentication details, consider encrypting the credentials or the enclosing data stores or configuration files, and using permissions to restrict access.

For web framework signing secrets, read the value from the environment or a secrets manager at runtime, and use a long, randomly generated value that is never committed to source control.

For inbound authentication details, consider hashing passwords using standard library functions where possible. For example, `hashlib.pbkdf2_hmac`.


## Example
The following examples shows different types of inbound and outbound authentication.

In the first case, we accept a password from a remote user, and compare it against a plaintext string literal. If an attacker acquires the source code they can observe the password, and can log in to the system. Furthermore, if such an intrusion was discovered, the application would need to be rewritten and redeployed in order to change the password.

In the second case, the password is compared to a hashed and salted password stored in a configuration file, using `hashlib.pbkdf2_hmac`. In this case, access to the source code or the assembly would not reveal the password to an attacker. Even access to the configuration file containing the password hash and salt would be of little value to an attacker, as it is usually extremely difficult to reverse engineer the password from the hash and salt.

In the final case, a password is changed to a new, hard-coded value. If an attacker has access to the source code, they will be able to observe the new password.


```python
import hashlib
import binascii

def process_request(request):
    password = request.GET["password"]

    # BAD: Inbound authentication made by comparison to string literal
    if password == "myPa55word":
        redirect("login")

    hashed_password = load_from_config('hashed_password', CONFIG_FILE)
    salt = load_from_config('salt', CONFIG_FILE)

    #GOOD: Inbound authentication made by comparing to a hash password from a config file.
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    hashed_input = binascii.hexlify(dk)
    if hashed_input == hashed_password:
        redirect("login")


```

The following example shows hard-coded framework signing secrets.


```python
import jwt
from flask import Flask

app = Flask(__name__)
# BAD: hard-coded Flask session secret
app.secret_key = "change-me-please"

# BAD: hard-coded JWT signing key
token = jwt.encode({"sub": "admin"}, "hardcoded-signing-key", algorithm="HS256")

# Django settings.py
# BAD: hard-coded Django secret key
SECRET_KEY = "secret"
# BAD: hard-coded SimpleJWT signing key
SIMPLE_JWT = {"SIGNING_KEY": SECRET_KEY}
```

Instead, read these secrets from the environment:


```python
import os

import jwt
from flask import Flask

app = Flask(__name__)
# GOOD: read from the environment
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# GOOD: signing key read from the environment
token = jwt.encode({"sub": "admin"}, os.environ["JWT_SIGNING_KEY"], algorithm="HS256")

# Django settings.py
# GOOD: read from the environment
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
SIMPLE_JWT = {"SIGNING_KEY": SECRET_KEY}
```

## References
* OWASP: [XSS Use of hard-coded password](https://www.owasp.org/index.php/Use_of_hard-coded_password).
* Flask: [SECRET_KEY](https://flask.palletsprojects.com/en/latest/config/#SECRET_KEY).
* Django: [SECRET_KEY](https://docs.djangoproject.com/en/stable/ref/settings/#secret-key).
* Common Weakness Enumeration: [CWE-259](https://cwe.mitre.org/data/definitions/259.html).
* Common Weakness Enumeration: [CWE-321](https://cwe.mitre.org/data/definitions/321.html).
* Common Weakness Enumeration: [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
