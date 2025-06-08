import secrets
from typing import Optional, Dict, Any
from pydantic import BaseSettings, field_validator

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "FastAPI JWT Auth"

    # security settings
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"  # In production, load from env

    class Config:
        env_file = ".env"

# Instantiate settings 
settings = Settings()

# This file is very useful for separating environment-specific values (like dev vs. production secrets) 
# without hardcoding them across your app.
