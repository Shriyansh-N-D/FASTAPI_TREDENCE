# schemas.py

from typing import List, Optional, Union
from pydantic import BaseModel, model_validator, ConfigDict
from datetime import datetime


class EntryCreate(BaseModel):
    UserName:      Optional[str] = None
    AppName:       Optional[str] = None
    prompt:        Optional[str] = None
    prompt_name:   Optional[str] = None
    user_prompt:   Optional[str] = None
    group_name:    Optional[str] = None
    sample_output: Optional[str] = None
    #tags:          Optional[List[str]] = None
    tags:          Optional[Union[List[str], str]] = None
    createdBy:     Optional[str] = None
    modifiedBy:    Optional[str] = None
    active:        Optional[bool] = True

    @model_validator(mode="before")
    def fill_missing_and_blank(cls, data: dict) -> dict:
        """
        Runs before any field validation. It:
         1) If a string field is missing or blank, sets it to "dummy_<fieldname>".
         2) If 'tags' is missing or None, sets it to 'default'.
        """
        string_fields = [
            "UserName",
            "AppName",
            "prompt",
            "prompt_name",
            "user_prompt",
            "group_name",
            "sample_output",
            "createdBy",
            "modifiedBy",
        ]
        for field_name in string_fields:
            val = data.get(field_name)
            if val is None or (isinstance(val, str) and not val.strip()):
                data[field_name] = f"dummy_{field_name}"

        # Default tags to "default" if missing or None
        if data.get("tags") is None:
            data["tags"] = "default"

        return data

    class Config:
        # No need for allow_population_by_field_name, since keys match exactly.
        pass


from pydantic import root_validator
import json

class EntryResponse(BaseModel):
    id: int
    UserName: str
    AppName: str
    prompt: str
    prompt_name: str
    user_prompt: str
    group_name: str
    sample_output: str
    tags: str  
    createdBy: str
    modifiedBy: str
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True  # V2 replacement for orm_mode = True



class EntryUpdate(BaseModel):
    UserName:      Optional[str] = None
    AppName:       Optional[str] = None
    prompt:        Optional[str] = None
    prompt_name:   Optional[str] = None
    user_prompt:   Optional[str] = None
    group_name:    Optional[str] = None
    sample_output: Optional[str] = None
    tags:          Optional[Union[List[str], str]] = None
    createdBy:     Optional[str] = None
    modifiedBy:    Optional[str] = None
    active:        Optional[bool] = None

    model_config = ConfigDict(from_attributes=True)



class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str  # plain-text; we'll hash before saving
    is_admin: bool = False

class UserRead(UserBase):
    id: int
    is_admin: bool

    class Config:
        from_attributes = True

from typing import Optional
from pydantic import BaseModel, ConfigDict

class Token(BaseModel):
    access_token: str
    token_type: str

    model_config = ConfigDict(from_attributes=True)

class TokenData(BaseModel):
    username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
