# JWT decoded with signature verification disabled
A JSON Web Token (JWT) is only trustworthy if its signature is checked against a secret or public key. PyJWT and python-jose allow signature checking to be turned off, either through `options={"verify_signature": False}` or, in PyJWT 1.x, through `verify=False`. When the decoded claims are then used to identify or authorize a user, an attacker can forge a token with arbitrary claims, for example to impersonate another user or escalate privileges.


## Recommendation
Always decode tokens with signature verification enabled, passing the expected key and an explicit list of allowed algorithms. If unverified claims are needed (for example to pick a key by its `kid` header), only use them to select the key and then decode the same token again with verification enabled before trusting any claim.


## Example
In the following example, the token is decoded with signature verification disabled by a module-level constant, so any token is accepted:


```python
import jwt

SECRET_KEY = "change-me"
VERIFY_SIGNATURE = False


def get_current_user(token):
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_signature": VERIFY_SIGNATURE},  # BAD
    )
    return payload["sub"]

```
The fix is to remove the option, so that the signature is verified with the secret key:


```python
import jwt

SECRET_KEY = "change-me"


def get_current_user(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # GOOD
    return payload["sub"]

```

## References
* CWE: [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html).
* PyJWT: [Reading the Claimset without Validation](https://pyjwt.readthedocs.io/en/stable/usage.html#reading-the-claimset-without-validation).
* OWASP: [JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html).
* Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html).
