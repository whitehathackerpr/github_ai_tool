import os
from pydantic_settings import BaseSettings
from typing import Dict, Any, List, Optional, Union
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings and configuration."""
    
    # Application
    APP_NAME: str = "GitHub AI Tool"
    APP_VERSION: str = "0.1.0"
    APP_DESCRIPTION: str = "AI-powered tool for GitHub repository analysis, code review, documentation generation, and issue/PR summarization"
    API_PREFIX: str = "/api"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Security
    ALLOWED_ORIGINS: List[str] = []
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    
    # GitHub
    GITHUB_CLIENT_ID: Optional[str] = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET: Optional[str] = os.getenv("GITHUB_CLIENT_SECRET")
    
    # Redis for caching
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD")
    REDIS_SSL: bool = os.getenv("REDIS_SSL", "False").lower() == "true"
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")  # Take precedence over host/port if set
    
    # Cache settings
    CACHE_EXPIRATION: int = int(os.getenv("CACHE_EXPIRATION", "3600"))  # 1 hour
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))  # requests
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
    
    # AI services
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    AI_MODEL: str = os.getenv("AI_MODEL", "gpt-3.5-turbo")
    
    # Background tasks
    BACKGROUND_WORKERS: int = int(os.getenv("BACKGROUND_WORKERS", "3"))
    
    # Temporary directory for cloned repositories
    TEMP_DIR: str = os.getenv("TEMP_DIR", "/tmp/github_ai_tool")

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)

# Ensure temporary directory exists
if not os.path.exists(settings.TEMP_DIR):
    try:
        os.makedirs(settings.TEMP_DIR, exist_ok=True)
        logger.info(f"Created temporary directory: {settings.TEMP_DIR}")
    except Exception as e:
        logger.warning(f"Failed to create temporary directory: {str(e)}")

import os
from pydantic_settings import BaseSettings
from typing import Dict, Any, List, Optional, Union
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings and configuration."""
    
    # Application
    APP_NAME: str = "GitHub AI Tool"
    APP_VERSION: str = "0.1.0"
    APP_DESCRIPTION: str = "AI-powered tool for GitHub repository analysis, code review, documentation generation, and issue/PR summarization"
    API_PREFIX: str = "/api"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_in_production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    
    # GitHub
    GITHUB_CLIENT_ID: Optional[str] = os.getenv("GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET: Optional[str] = os.getenv("GITHUB_CLIENT_SECRET")
    
    # Redis for caching
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: Optional[str] = os.getenv("REDIS_PASSWORD")
    REDIS_SSL: bool = os.getenv("REDIS_SSL", "False").lower() == "true"
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")  # Take precedence over host/port if set
    
    # Cache settings
    CACHE_EXPIRATION: int = int(os.getenv("CACHE_EXPIRATION", "3600"))  # 1 hour
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))  # requests
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
    
    # AI services
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    
    # Background tasks
    BACKGROUND_WORKERS: int = int(os.getenv("BACKGROUND_WORKERS", "3"))

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

