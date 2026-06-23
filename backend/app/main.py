import json
import logging
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select, func
from datetime import datetime, timedelta
from typing import Optional

from app.config import settings
from app.db import (
    engine, init_db, get_session, User, Alert, UserCreate, UserResponse, Token, PredictionRequest
)
from app.auth import (
    get_password_hash, verify_password, create_access_token, get_current_user
)
from app.ml.cascade import CascadeDetector, get_detector
from app.simulator import simulator_engine
from pydantic import BaseModel
from typing import Optional

class SimulateStartRequest(BaseModel):
    scenario: str
    rate: int = 1
    duration_seconds: Optional[int] = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- WEBSOCKET CONNECTION MANAGER ---

class ConnectionManager:
    """Manages active live WebSocket connections for real-time telemetry."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New client connected to WebSocket. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Client disconnected from WebSocket. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Sends a JSON-serializable dictionary to all active WebSocket clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Error broadcasting to client: {e}")
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)

# Global connection manager instance
manager = ConnectionManager()

async def broadcast_detection(result: dict):
    """Broadcasting helper to send threat classification results to the live feed."""
    event = {
        "event": "detection",
        "data": result,
        "timestamp": datetime.utcnow().isoformat()
    }
    await manager.broadcast(event)

async def send_heartbeat():
    """Periodic background worker sending heartbeat ping event to connected frontends."""
    while True:
        try:
            await asyncio.sleep(5)  # 5-second interval
            heartbeat_msg = {
                "event": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            }
            await manager.broadcast(heartbeat_msg)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize SQLite Database Tables (creates /data/cache/app.db)
    logger.info("Initializing database tables on startup...")
    init_db()
    
    # 2. Seed default admin user on first run if not exists
    with Session(engine) as session:
        statement = select(User).where(User.role == "admin")
        admin = session.exec(statement).first()
        if not admin:
            import secrets
            # Generate a secure random password
            admin_password = "Admin@" + secrets.token_hex(4) + "!"
            hashed_pwd = get_password_hash(admin_password)
            admin_user = User(
                username="admin",
                hashed_password=hashed_pwd,
                role="admin"
            )
            session.add(admin_user)
            session.commit()
            
            # Print credentials prominently in a clean visual banner on stdout
            logger.info(
                "\n" + "=" * 80 +
                "\n          [SEEDING DEFAULT ADMIN USER] FIRST TIME RUN ONLY" +
                "\n" + "=" * 80 +
                "\n  An administrative user has been successfully seeded in the database." +
                f"\n  Username: admin" +
                f"\n  Password: {admin_password}" +
                "\n  Role:     admin" +
                "\n" + "=" * 80
            )
            
    # 3. Load Cascade Detector into memory once
    logger.info("Initializing CascadeDetector models (this may take a few seconds)...")
    try:
        app.state.detector = get_detector()
        logger.info("CascadeDetector successfully loaded and cached in application state.")
    except Exception as e:
        logger.error(f"Failed to load CascadeDetector: {e}")
        
    # 4. Initialize Simulation Engine index mappings
    try:
        simulator_engine.initialize()
    except Exception as e:
        logger.error(f"Failed to initialize simulator engine indices: {e}")
        
    # 5. Start background heartbeat task
    logger.info("Starting background WebSocket heartbeat loop...")
    heartbeat_task = asyncio.create_task(send_heartbeat())
    
    yield
    
    # Clean up background task on shutdown
    logger.info("Stopping simulator engine if active...")
    simulator_engine.stop()
    
    logger.info("Stopping background WebSocket heartbeat task...")
    heartbeat_task.cancel()
    try:
        await heartbeat_task
    except asyncio.CancelledError:
        pass
    logger.info("Application shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Backend API for Cybersecurity Threat Simulator Powered by AI",
    version="0.1.0",
    lifespan=lifespan
)

# Configure CORS specifically for Vite dev server and local script probes
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {
        "message": f"Welcome to the {settings.PROJECT_NAME} API",
        "docs_url": "/docs",
        "health_check": "/api/health"
    }

@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend connectivity."""
    return {"status": "ok"}

# --- AUTHENTICATION ROUTES ---

@app.post("/api/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user_in: UserCreate, session: Session = Depends(get_session)):
    """Public endpoint to register a new user analyst account."""
    # Check if user already exists
    statement = select(User).where(User.username == user_in.username)
    existing_user = session.exec(statement).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )
        
    # Create new user
    hashed_pwd = get_password_hash(user_in.password)
    new_user = User(username=user_in.username, hashed_password=hashed_pwd)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    """Authenticates username/password and returns a JWT token containing sub + role claims."""
    statement = select(User).where(User.username == form_data.username)
    user = session.exec(statement).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # Sign token containing sub and role claims
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns the logged-in analyst's profile details."""
    return current_user

# --- ML CASCADE PREDICTION & METRICS ---

@app.post("/api/predict")
async def predict_flow(
    request: PredictionRequest, 
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Receives raw network packet features, runs cascade detection, and records threat alerts (Protected)."""
    detector: CascadeDetector = getattr(app.state, "detector", None)
    if detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Machine learning cascade detector is not loaded yet."
        )
        
    try:
        # Run detection (needs to run in main thread or run pool if blocking, but it's fast enough)
        result = detector.detect(request.features)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Inference failed: {e}"
        )
        
    # If the label is not BENIGN, record an alert in the SQLite database
    label = result["predicted_label"]
    if label.upper() != "BENIGN":
        alert = Alert(
            predicted_label=label,
            confidence=result["confidence"],
            tier=result["tier"],
            source_scenario=request.source_scenario or "simulation",
            raw_features=json.dumps(request.features)
        )
        session.add(alert)
        session.commit()
        session.refresh(alert)
        result["alert_id"] = alert.id
        result["source_scenario"] = alert.source_scenario
        logger.info(f"Threat Alert recorded [ID: {alert.id}]: {label} (Scenario: {alert.source_scenario}, Tier: {alert.tier})")
        
    # Broadcast classification result to all connected WebSocket clients instantly
    await broadcast_detection(result)
        
    return result

@app.get("/api/models/metrics")
def get_models_metrics():
    """Reads and returns trained evaluation summaries and confusion matrix arrays."""
    metrics_dir = Path(settings.DATA_CACHE_DIR) / "metrics"
    summary_path = metrics_dir / "summary.json"
    
    if not summary_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metrics summary not found. Ensure models are trained first."
        )
        
    try:
        with open(summary_path, "r") as f:
            summary = json.load(f)
            
        conf_matrices = {}
        for model in ["lightgbm", "random_forest", "xgboost"]:
            cm_path = metrics_dir / f"{model}_conf_matrix.json"
            if cm_path.exists():
                with open(cm_path, "r") as f:
                    conf_matrices[model] = json.load(f)
                    
        return {
            "summary": summary,
            "confusion_matrices": conf_matrices
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read evaluation metrics: {e}"
        )

# --- ALERTS LOG RETRIEVAL & STATS ---

@app.get("/api/alerts")
def get_alerts(
    attack_type: Optional[str] = None,
    tier: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    page: int = 1,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Returns a list of threat alerts from SQLite with support for filtering and pagination (Protected)."""
    statement = select(Alert)
    
    # Apply filters
    if attack_type:
        statement = statement.where(Alert.predicted_label == attack_type)
    if tier is not None:
        statement = statement.where(Alert.tier == tier)
    if date_from:
        statement = statement.where(Alert.timestamp >= date_from)
    if date_to:
        statement = statement.where(Alert.timestamp <= date_to)
        
    # Sort newest first
    statement = statement.order_by(Alert.timestamp.desc())
    
    # Pagination
    offset = (page - 1) * limit
    statement = statement.offset(offset).limit(limit)
    
    alerts = session.exec(statement).all()
    
    # Parse JSON strings back to dict before returning
    parsed_alerts = []
    for alert in alerts:
        parsed_alerts.append({
            "id": alert.id,
            "timestamp": alert.timestamp,
            "predicted_label": alert.predicted_label,
            "confidence": alert.confidence,
            "tier": alert.tier,
            "source_scenario": alert.source_scenario,
            "raw_features": json.loads(alert.raw_features)
        })
    return parsed_alerts

@app.get("/api/alerts/stats")
def get_alerts_stats(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Returns alert counts grouped by attack type and by resolution tier (Protected)."""
    # Count by attack type (predicted_label)
    attack_type_statement = select(Alert.predicted_label, func.count(Alert.id)).group_by(Alert.predicted_label)
    attack_type_counts = session.exec(attack_type_statement).all()
    
    # Count by tier
    tier_statement = select(Alert.tier, func.count(Alert.id)).group_by(Alert.tier)
    tier_counts = session.exec(tier_statement).all()
    
    return {
        "by_attack_type": {label: count for label, count in attack_type_counts},
        "by_tier": {tier: count for tier, count in tier_counts}
    }

# --- SIMULATOR ROUTE ---

@app.get("/api/simulate")
def simulate_endpoint(current_user: User = Depends(get_current_user)):
    """Returns status indicator for the simulation flow engine (Protected)."""
    return {
        "status": "ready",
        "active_scenarios": ["ddos_storm", "port_scan", "brute_force", "mixed_attack", "benign_baseline"],
        "triggered_by": current_user.username,
        "analyst_role": current_user.role
    }

@app.post("/api/simulate/start")
async def simulate_start(
    req: SimulateStartRequest,
    current_user: User = Depends(get_current_user)
):
    """Starts a safe data-replay simulation scenario at a given packets/sec rate (Protected)."""
    if req.rate <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Simulation rate must be at least 1 packet per second."
        )
    try:
        simulator_engine.start(req.scenario, req.rate, req.duration_seconds)
        return {
            "status": "started",
            "scenario": req.scenario,
            "rate": req.rate,
            "duration_seconds": req.duration_seconds,
            "triggered_by": current_user.username
        }
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start simulation: {e}"
        )

@app.post("/api/simulate/stop")
async def simulate_stop(current_user: User = Depends(get_current_user)):
    """Stops the active simulation (Protected)."""
    if not simulator_engine.is_running:
        return {"status": "not_running", "message": "No active simulation is running."}
    
    simulator_engine.stop()
    return {
        "status": "stopped",
        "stopped_by": current_user.username
    }

@app.get("/api/simulate/status")
def simulate_status(current_user: User = Depends(get_current_user)):
    """Retrieves current simulation running status, scenario details, and telemetry counters (Protected)."""
    return simulator_engine.get_status()

# --- WEBSOCKET LIVE ROUTE ---

@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """Exposes real-time event socket feed for dashboard synchronization."""
    await manager.connect(websocket)
    try:
        while True:
            # We await incoming frames to capture close codes and disconnects cleanly
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("WebSocket disconnect event registered cleanly.")
    except Exception as e:
        logger.info(f"WebSocket client connection closed: {e}")
    finally:
        manager.disconnect(websocket)
