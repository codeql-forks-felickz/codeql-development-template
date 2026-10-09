from typing import Union

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Extra

router = APIRouter()


class User:
    """Stand-in for a SQLAlchemy database model."""

    username: str
    first_name: str
    role: str


def get_current_user() -> User:
    return User()


ALLOWED_FIELDS = {"first_name", "last_name"}


# Pydantic v2: `model_config = ConfigDict(extra="allow")`
class UpdateUserV2(BaseModel):
    model_config = ConfigDict(extra="allow")

    first_name: Union[str, None] = None


# Pydantic v2: dict literal `model_config`
class UpdateUserDict(BaseModel):
    model_config = {"extra": "allow"}

    first_name: Union[str, None] = None


# Pydantic v1: class keyword argument
class UpdateUserKwarg(BaseModel, extra=Extra.allow):
    first_name: Union[str, None] = None


# Pydantic v1: inner `Config` class
class UpdateUserInnerConfig(BaseModel):
    first_name: Union[str, None] = None

    class Config:
        extra = "allow"


# Subclass of a model that allows extra fields
class UpdateUserChild(UpdateUserV2):
    last_name: Union[str, None] = None


# Extra fields are rejected or ignored
class UpdateUserForbid(BaseModel):
    model_config = ConfigDict(extra="forbid")

    first_name: Union[str, None] = None


class UpdateUserDefault(BaseModel):
    first_name: Union[str, None] = None


# Subclass that overrides an inherited extra="allow"
class UpdateUserChildIgnore(UpdateUserV2):
    model_config = ConfigDict(extra="ignore")


@router.patch("/v2")
def patch_v2(body: UpdateUserV2, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)  # $ Alert
    return user


@router.patch("/dict")
def patch_dict(body: UpdateUserDict, user: User = Depends(get_current_user)):
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(user, key, value)  # $ Alert
    return user


@router.patch("/kwarg")
def patch_kwarg(body: UpdateUserKwarg, user: User = Depends(get_current_user)):
    for var, value in body.dict().items():
        if value:
            setattr(user, var, value)  # $ Alert
    return user


@router.patch("/inner-config")
def patch_inner_config(body: UpdateUserInnerConfig, user: User = Depends(get_current_user)):
    data = body.dict()
    for k, v in data.items():
        setattr(user, k, v)  # $ Alert
    return user


@router.patch("/child")
def patch_child(body: UpdateUserChild, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)  # $ Alert
    return user


@router.patch("/validated")
def patch_validated(raw: dict, user: User = Depends(get_current_user)):
    body = UpdateUserV2.model_validate(raw)
    for k, v in body.model_dump().items():
        setattr(user, k, v)  # $ Alert
    return user


@router.patch("/vars")
def patch_vars(body: UpdateUserKwarg, user: User = Depends(get_current_user)):
    for var, value in vars(body).items():
        setattr(user, var, value)  # $ Alert
    return user


# --- Safe cases ---


@router.patch("/child-ignore")
def patch_child_ignore(body: UpdateUserChildIgnore, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)
    return user


@router.patch("/forbid")
def patch_forbid(body: UpdateUserForbid, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)
    return user


@router.patch("/default")
def patch_default(body: UpdateUserDefault, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        setattr(user, k, v)
    return user


@router.patch("/allowlist")
def patch_allowlist(body: UpdateUserV2, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        if k in ALLOWED_FIELDS:
            setattr(user, k, v)
    return user


@router.patch("/allowlist-continue")
def patch_allowlist_continue(body: UpdateUserV2, user: User = Depends(get_current_user)):
    for k, v in body.model_dump().items():
        if k not in ALLOWED_FIELDS:
            continue
        setattr(user, k, v)
    return user


@router.patch("/include")
def patch_include(body: UpdateUserV2, user: User = Depends(get_current_user)):
    for k, v in body.model_dump(include={"first_name"}).items():
        setattr(user, k, v)
    return user


@router.patch("/explicit")
def patch_explicit(body: UpdateUserV2, user: User = Depends(get_current_user)):
    user.first_name = body.first_name
    return user
