from pydantic import BaseModel
from typing import Optional, List

# This is what your token endpoint returns
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    
# Represents the decoded JWT payload
class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None
    roles: List[str] = []

# Internal model used for user authentication state
class TokenData(BaseModel):
    username: Optional[str] = None
    roles: List[str] = ["user"]
