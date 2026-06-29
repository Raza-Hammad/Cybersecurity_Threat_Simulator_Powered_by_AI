from sqlmodel import SQLModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class User(SQLModel, table=True):
    """Database model for application users authentication."""
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    role: str = Field(default="analyst")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Alert(SQLModel, table=True):
    """Database model for security threat alerts triggered by malicious flows."""
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    predicted_label: str
    confidence: float
    tier: int
    source_scenario: str = Field(default="simulation")
    severity: str = Field(default="Medium")
    source_ip: str = Field(default="10.0.0.1")
    dest_ip: str = Field(default="192.168.10.50")
    source_port: int = Field(default=0)
    dest_port: int = Field(default=0)
    raw_features: str = Field(default="{}")  # JSON-encoded input feature dictionary

class UserCreate(SQLModel):
    """Schema for user registration requests."""
    username: str
    password: str

class UserResponse(SQLModel):
    """Schema for user detail responses."""
    id: int
    username: str
    role: str
    created_at: datetime

class Token(SQLModel):
    """Schema for authentication access tokens."""
    access_token: str
    token_type: str

class TokenData(SQLModel):
    """Schema for data stored within JWT payloads."""
    username: Optional[str] = None

class PredictionRequest(SQLModel):
    """Schema for incoming prediction request packet data."""
    features: Dict[str, Any]
    source_scenario: Optional[str] = "simulation"
