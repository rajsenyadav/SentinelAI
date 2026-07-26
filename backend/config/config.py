"""
SentinelAI Backend — Configuration Management

Centralized configuration loaded from environment variables and yaml settings using Pydantic.
"""

import os

try:
    from pydantic_settings import BaseSettings
except ImportError:
    try:
        from pydantic import BaseSettings
    except ImportError:
        from pydantic import BaseModel as BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "SentinelAI Risk Intelligence API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_RAW_DIR: str = os.path.join(BASE_DIR, "data", "raw")
    DATA_PROCESSED_DIR: str = os.path.join(BASE_DIR, "data", "processed")
    MODEL_DIR: str = os.path.join(BASE_DIR, "models")
    REPORT_DIR: str = os.path.join(BASE_DIR, "reports")

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
