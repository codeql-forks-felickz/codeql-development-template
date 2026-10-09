# Mass assignment from a request model that allows extra fields

A Pydantic model configured with `extra="allow"` keeps every field the client sends, not only the fields declared on the model. If the application then copies every parsed field onto another object (for example a SQLAlchemy database model) using `setattr` in a loop, a client can set any attribute of that object, including privileged ones such as `role` or `is_admin`. This is a mass assignment vulnerability.

This query is a heuristic: it looks for a loop over the `.items()` of `model_dump()`, `dict()` or `vars()` of such a model instance whose key is passed to `setattr`.

## Recommendation

Do not accept arbitrary extra fields on request models (use the default `extra="ignore"` or `extra="forbid"`). Copy only an explicit allowlist of fields, either by assigning them individually, by checking the key against an allowlist before calling `setattr`, or by passing `include=` to `model_dump()`.

## Example

In the following example, the `UpdateUser` model accepts extra fields and every field is copied onto the current user, so a request body such as `{"role": "admin"}` escalates privileges:

```python
from fastapi import Depends
from pydantic import BaseModel, ConfigDict


class UpdateUser(BaseModel):
    model_config = ConfigDict(extra="allow")

    first_name: str | None = None


@router.patch("/profile")
def patch_profile(body: UpdateUser, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)  # BAD
```

The fix is to forbid extra fields and to copy only allowlisted fields:

```python
class UpdateUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first_name: str | None = None


ALLOWED_FIELDS = {"first_name"}


@router.patch("/profile")
def patch_profile(body: UpdateUser, user: User = Depends(get_current_user)):
    for k, v in body.model_dump(exclude_unset=True).items():
        if k in ALLOWED_FIELDS:
            setattr(user, k, v)  # GOOD
```

## References

- OWASP: [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
- Pydantic: [Extra attributes](https://docs.pydantic.dev/latest/concepts/models/#extra-data).
- Common Weakness Enumeration: [CWE-915](https://cwe.mitre.org/data/definitions/915.html).
