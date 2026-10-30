# JWT payload decoded manually without signature verification
A JSON Web Token (JWT) has three base64url-encoded segments separated by dots: a header, the claims, and a signature. Some code extracts the claims by hand, by splitting the token on `"."`, base64-decoding the second segment and parsing it as JSON, without ever checking the third (signature) segment. Since anyone can encode arbitrary claims, an attacker can then impersonate any user, for example an administrator.

This query flags such hand-written decoding when the signature segment of the split token is never read. It is a heuristic, so code that verifies the token elsewhere (for example in an API gateway authorizer) may be reported.


## Recommendation
Decode tokens with a JWT library such as PyJWT, passing the expected key and an explicit list of allowed algorithms, so that the signature is verified before any claim is trusted. If the token is verified by another component, document that and make sure the handler cannot be reached without it.


## Example
In the following example, the acting user is taken from the claims segment of the `Authorization` header without verifying the signature:


```python
import base64
import json


def lambda_handler(event, context):
    token_sections = event["headers"]["Authorization"].split(".")
    auth_data = base64.b64decode(token_sections[1] + "==")  # BAD: signature never checked
    user = json.loads(auth_data)["username"]
    return user

```
The fix is to decode the token with a library that verifies the signature:


```python
import os

import jwt

SECRET_KEY = os.environ["JWT_SECRET_KEY"]


def lambda_handler(event, context):
    token = event["headers"]["Authorization"]
    claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # GOOD
    return claims["username"]

```

## References
* CWE: [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html).
* IETF: [RFC 7519, Section 7.2: Validating a JWT](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2).
* PyJWT: [Usage Examples](https://pyjwt.readthedocs.io/en/stable/usage.html).
* Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html).
