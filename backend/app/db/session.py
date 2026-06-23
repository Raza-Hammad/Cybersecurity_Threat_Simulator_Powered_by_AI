from sqlmodel import SQLModel, create_engine, Session
from app.config import settings

# Setup SQLite database engine. check_same_thread=False allows FastAPI multithreaded requests to query SQLite.
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

def init_db():
    """Initializes tables in the SQLite database based on SQLModel metadata."""
    # Importing models here ensures they are registered with SQLModel metadata before creation
    from app.db.models import User, Alert
    SQLModel.metadata.create_all(engine)

def get_session():
    """Dependency generator yielding a clean database session context per request."""
    with Session(engine) as session:
        yield session
