import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file if it exists
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Settings:
    PROJECT_NAME: str = "Cybersecurity Threat Simulator Powered by AI"
    API_V1_STR: str = "/api"
    
    # Secrets
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-jwt-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week
    
    # Data Directories
    DATA_RAW_DIR: str = os.getenv("DATA_RAW_DIR", str(BASE_DIR.parent / "data" / "raw"))
    DATA_CACHE_DIR: str = os.getenv("DATA_CACHE_DIR", str(BASE_DIR.parent / "data" / "cache"))
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{Path(DATA_CACHE_DIR) / 'app.db'}")
    
    # Server configuration
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", 8000))

settings = Settings()
