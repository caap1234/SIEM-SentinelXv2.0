from pydantic import BaseModel
from typing import Optional


class UserBase(BaseModel):
    email: str
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str
    is_admin: bool = False


class UserLogin(BaseModel):
    email: str
    password: str


class UserInDB(UserBase):
    id: int
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True


class UserPublic(UserBase):
    id: int
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True
