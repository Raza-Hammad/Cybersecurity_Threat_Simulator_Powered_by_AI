import json
import logging
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select, func
from datetime import datetime, timedelta
from typing import Optional
from io import BytesIO

from app.config import settings
from app.db import (
    engine, init_db, get_session, User, Alert, UserCreate, UserResponse, Token, PredictionRequest
)
from app.auth import (
    get_password_hash, verify_password, create_access_token, get_current_user
)
from app.ml.cascade import CascadeDetector, get_detector
from app.ml.severity import compute_severity
from app.ml.metadata_helper import get_raw_flow_metadata
from app.simulator import simulator_engine
from pydantic import BaseModel
from typing import Optional, Dict, Any

class SimulateStartRequest(BaseModel):
    scenario: str
    rate: int = 1
    duration_seconds: Optional[int] = None

class XaiRequest(BaseModel):
    predicted_label: str
    confidence: float
    tier: int
    features: Dict[str, Any]

class ChatRequest(BaseModel):
    message: str

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
            # Seed default admin user password
            admin_password = "Admin@652f0915!"
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
        
    label = result["predicted_label"]
    # Determine IP/Port display metadata using deterministic hash of features
    import hashlib
    features_hash = hashlib.md5(json.dumps(request.features).encode('utf-8')).hexdigest()
    idx = int(features_hash, 16) % 1000000
    src_ip, dest_ip, src_port, dest_port = get_raw_flow_metadata(idx, label)
    result["source_ip"] = src_ip
    result["dest_ip"] = dest_ip
    result["source_port"] = src_port
    result["dest_port"] = dest_port

    # If the label is not BENIGN, record an alert in the SQLite database
    if label.upper() != "BENIGN":
        alert = Alert(
            predicted_label=label,
            confidence=result["confidence"],
            tier=result["tier"],
            source_scenario=request.source_scenario or "simulation",
            severity=result.get("severity", "Medium"),
            source_ip=src_ip,
            dest_ip=dest_ip,
            source_port=src_port,
            dest_port=dest_port,
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

# Configure Gemini API client
if settings.GEMINI_API_KEY:
    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GEMINI_API_KEY)
    except Exception as gem_err:
        logger.error(f"Failed to configure Gemini client: {gem_err}")

@app.post("/api/xai/explain")
async def explain_packet(
    req: XaiRequest,
    current_user: User = Depends(get_current_user)
):
    """Generates a plain-English explanation for a flagged packet flow (Protected)."""
    detector: CascadeDetector = getattr(app.state, "detector", None)
    if detector is None:
        detector = get_detector()
        
    try:
        result = detector.detect(req.features)
        top_features = result.get("top_features", [])
    except Exception as e:
        logger.warning(f"Failed to align features in explain endpoint: {e}")
        top_features = []

    features_desc_list = []
    for feat in top_features:
        name = feat.get("feature")
        val = feat.get("value", 0.0)
        benign_avg = feat.get("benign_avg", 0.0)
        features_desc_list.append(
            f"- {name}: Value = {val:.4f} (Benign Baseline Average = {benign_avg:.4f})"
        )
    features_str = "\n".join(features_desc_list)
    
    tier_names = {
        1: "Tier 1: LightGBM (Fast Volumetric Screener)",
        2: "Tier 2: Random Forest (Explainable Validator)",
        3: "Tier 3: Expert Ensemble & Weighted Vote"
    }
    tier_name = tier_names.get(req.tier, f"Tier {req.tier} Classifier")

    explanation = None
    if settings.GEMINI_API_KEY:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f"""
            You are a security operations center (SOC) AI analyst.
            Provide exactly one plain-English sentence explaining why this network flow was classified as '{req.predicted_label}' by the ML cascade.
            Keep the sentence professional, highly technical but readable, and direct. Mention specific values and comparison with their benign baseline averages if appropriate.
            
            Resolution Tier: {tier_name}
            Confidence level: {req.confidence:.2%}
            Top contributing packet features:
            {features_str}
            
            Format instructions:
            Provide exactly one natural, readable sentence. Do NOT use markdown bolding, asterisks (*), or lists in the output sentence. Do not say "Based on the provided information..." or similar intro phrases.
            """
            loop = asyncio.get_running_loop()
            def call_gemini():
                res = model.generate_content(prompt)
                return res.text.strip()
                
            explanation = await loop.run_in_executor(None, call_gemini)
            explanation = explanation.replace("*", "").replace("`", "").strip()
        except Exception as api_err:
            logger.error(f"Gemini API execution error: {api_err}")
            explanation = None

    if not explanation:
        if top_features:
            primary_feat = top_features[0]
            name = primary_feat.get("feature")
            val = primary_feat.get("value", 0.0)
            benign_avg = primary_feat.get("benign_avg", 0.0)
            explanation = (
                f"This flow was flagged as a potential {req.predicted_label} threat by {tier_name} (Confidence: {req.confidence:.1%}) "
                f"primarily because the feature '{name}' was measured at {val:.2f}, which deviates significantly from the benign average of {benign_avg:.2f}."
            )
        else:
            explanation = (
                f"This flow was flagged as a potential {req.predicted_label} threat by {tier_name} (Confidence: {req.confidence:.1%}) "
                f"based on multivariate feature anomalies matching threat signatures."
            )

    return {
        "verdict": req.predicted_label,
        "confidence": req.confidence,
        "tier": req.tier,
        "tier_name": tier_name,
        "top_features": top_features,
        "explanation": explanation,
        "benign_averages": result.get("benign_averages", {}) if 'result' in locals() else {},
        "severity": compute_severity(req.predicted_label, req.confidence)
    }


RULES_QA = [
    {
        "keywords": ["how does the cascade work", "cascade logic", "explain cascade", "cascade pipeline"],
        "answer": "The threat detection system utilizes a 3-tier cascade to maximize throughput and explainability. Tier 1 (LightGBM) screens 90%+ clear-cut benign flows instantly (~10μs). Tier 2 (Random Forest) validates uncertain cases (~3μs). Low-confidence anomalies escalate to Tier 3 (Expert Ensemble) for a weighted vote (LGBM 0.2 / RF 0.3 / XGB 0.5) to resolve the final alert verdict.",
        "source": "Rule-Based"
    },
    {
        "keywords": ["ddos", "distributed denial of service", "storm preset"],
        "answer": "The DDoS storm simulation preset replays high-volume SYN/UDP flooding traffic. It is characterized by high packet rates, large backward/forward packet counts, and elevated TCP window sizes (Init_Win_bytes_forward).",
        "source": "Rule-Based"
    },
    {
        "keywords": ["port scan", "portscan", "reconnaissance"],
        "answer": "The Port Scan simulation preset replays scanning traffic (SYN, ACK, NULL, FIN scans). It maps open host ports and is identified by low flow duration, high forward packet rates, and empty payloads.",
        "source": "Rule-Based"
    },
    {
        "keywords": ["brute force", "bruteforce", "credential stuffing"],
        "answer": "The Brute Force simulation preset replays SSH/FTP credential-stuffing login attempts. It features repeated connection attempts, small data transfers, and standard patterns in TCP handshake intervals.",
        "source": "Rule-Based"
    },
    {
        "keywords": ["what is the threshold", "confidence threshold", "escalation threshold"],
        "answer": "The escalation threshold is set to 0.85 (85%) by default. If a classifier's prediction confidence is below 0.85, the flow escalates to the next tier in the cascade.",
        "source": "Rule-Based"
    },
    {
        "keywords": ["who created this", "about this project", "project creator"],
        "answer": "This is the AI-Powered Cybersecurity Threat Simulator, designed by Antigravity for security operations analysts to safely simulate threat replays and study Cascade ML explainability.",
        "source": "Rule-Based"
    }
]

@app.post("/api/chat")
async def chat_assistant(
    req: ChatRequest,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Provides security operations intelligence through rule-based lookup and Gemini fallback (Protected)."""
    user_msg = req.message.strip()
    user_msg_lower = user_msg.lower()
    
    # 1. Check for "explain last alert" trigger
    is_last_alert_query = any(k in user_msg_lower for k in [
        "last alert", "last threat", "last attack", "latest alert", "latest threat", "latest attack", "explain the last"
    ])
    
    latest_alert_details = None
    if is_last_alert_query:
        # Retrieve latest alert from DB
        stmt = select(Alert).order_by(Alert.id.desc()).limit(1)
        alert = session.exec(stmt).first()
        if alert:
            try:
                features = json.loads(alert.raw_features)
            except Exception:
                features = {}
                
            detector = getattr(app.state, "detector", None) or get_detector()
            try:
                result = detector.detect(features)
                top_feats = result.get("top_features", [])
            except Exception:
                top_feats = []
                
            feats_str = ", ".join([f"'{f['feature']}'={f['value']:.2f} (benign avg: {f['benign_avg']:.2f})" for f in top_feats])
            latest_alert_details = (
                f"Latest logged alert [ID {alert.id}] at {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}. "
                f"Verdict: {alert.predicted_label} (Confidence: {alert.confidence:.2%}, Resolved by Tier {alert.tier}). "
                f"Top attributing features: {feats_str}."
            )
        else:
            latest_alert_details = "No alerts have been recorded in the database yet."

        if not settings.GEMINI_API_KEY:
            return {
                "answer": f"Here is the details of the latest logged security event:\n{latest_alert_details}",
                "source": "Rule-Based"
            }

    # 2. Check for rule-based keywords
    if not is_last_alert_query:
        for rule in RULES_QA:
            if any(kw in user_msg_lower for kw in rule["keywords"]):
                return {
                    "answer": rule["answer"],
                    "source": rule["source"]
                }
                
    # 3. Fall back to Gemini API if configured
    if settings.GEMINI_API_KEY:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            system_instruction = (
                "You are a helpful, professional cybersecurity operations center (SOC) AI assistant for this Threat Simulator portal. "
                "You answer questions ONLY related to cybersecurity, network traffic patterns, machine learning intrusion detection (LightGBM, Random Forest, XGBoost), the 3-tier cascade detector, or general SOC analyst guidelines. "
                "If the question is off-topic (e.g. cooking, travel, general off-topic chat, non-cybersecurity topics), politely decline to answer, stating that you can only assist with security intelligence for this project."
            )
            
            prompt = f"{system_instruction}\n\n"
            if latest_alert_details:
                prompt += f"Context on the latest recorded security threat alert: {latest_alert_details}\n\n"
                
            prompt += f"User message: {user_msg}"
            
            loop = asyncio.get_running_loop()
            def call_gemini():
                res = model.generate_content(prompt)
                return res.text.strip()
                
            answer = await loop.run_in_executor(None, call_gemini)
            answer = answer.replace("*", "").replace("`", "").strip()
            return {
                "answer": answer,
                "source": "AI Gemini"
            }
        except Exception as e:
            logger.error(f"Gemini API chat invocation failed: {e}")
            
    # 4. Fallback response if offline
    if is_last_alert_query and latest_alert_details:
        return {
            "answer": f"Here is a summary of the latest security event:\n{latest_alert_details}",
            "source": "Rule-Based"
        }
        
    return {
        "answer": "I am currently operating in offline mode. Please ask about the cascade architecture, simulator presets, or specific threat types (DDoS, Port Scan, Brute Force).",
        "source": "Offline Fallback"
    }


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
                    
        # Extract feature importances from the Random Forest model dynamically
        feature_importances = []
        try:
            detector = get_detector()
            if detector and hasattr(detector, "models") and "random_forest" in detector.models:
                rf = detector.models["random_forest"]
                importances = rf.feature_importances_
                features = detector.selected_features
                feature_importances = [
                    {"feature": name, "importance": float(imp)}
                    for name, imp in zip(features, importances)
                ]
                # Sort descending
                feature_importances.sort(key=lambda x: x["importance"], reverse=True)
        except Exception as xai_err:
            logger.error(f"Failed to extract RF feature importances: {xai_err}")

        return {
            "summary": summary,
            "confusion_matrices": conf_matrices,
            "feature_importances": feature_importances
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
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "source_port": alert.source_port,
            "dest_port": alert.dest_port,
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


@app.get("/api/data/smote-stats")
def get_smote_stats():
    """Reads and returns the oversampling stats generated by the SMOTE data preprocessor (Protected)."""
    smote_path = Path(settings.DATA_CACHE_DIR) / "smote_stats.json"
    if not smote_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SMOTE oversampling stats not found. Ensure dataset preprocessor has run."
        )
    try:
        with open(smote_path, "r") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read SMOTE stats: {str(e)}"
        )


@app.get("/api/alerts/export")
def export_alerts(
    format: str = "pdf",
    attack_type: Optional[str] = None,
    tier: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    """Generates an in-memory session report of filtered alerts in PDF or CSV format (Protected)."""
    statement = select(Alert)
    if attack_type:
        statement = statement.where(Alert.predicted_label == attack_type)
    if tier is not None:
        statement = statement.where(Alert.tier == tier)
    if date_from:
        statement = statement.where(Alert.timestamp >= date_from)
    if date_to:
        statement = statement.where(Alert.timestamp <= date_to)
        
    statement = statement.order_by(Alert.timestamp.desc())
    alerts = session.exec(statement).all()

    total_alerts = len(alerts)
    by_tier = {1: 0, 2: 0, 3: 0}
    by_attack = {}
    for alert in alerts:
        by_tier[alert.tier] = by_tier.get(alert.tier, 0) + 1
        by_attack[alert.predicted_label] = by_attack.get(alert.predicted_label, 0) + 1

    if format.lower() == "csv":
        import csv
        from io import StringIO
        csv_buffer = StringIO()
        writer = csv.writer(csv_buffer)
        
        # Write metadata headers
        writer.writerow(["--- AI SOC TELEMETRY EXPORT REPORT ---"])
        writer.writerow(["Generated At", datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(["Query Date From", date_from.strftime('%Y-%m-%d %H:%M:%S') if date_from else "All Time"])
        writer.writerow(["Query Date To", date_to.strftime('%Y-%m-%d %H:%M:%S') if date_to else "Present"])
        writer.writerow([])
        
        # Write summary stats
        writer.writerow(["SUMMARY STATISTICS"])
        writer.writerow(["Total Alerts", total_alerts])
        writer.writerow(["Tier 1 (LightGBM)", by_tier[1]])
        writer.writerow(["Tier 2 (Random Forest)", by_tier[2]])
        writer.writerow(["Tier 3 (Expert Ensemble)", by_tier[3]])
        writer.writerow([])
        
        # Write alerts
        writer.writerow(["INCIDENT LOG TABLE"])
        writer.writerow(["Alert ID", "Timestamp (UTC)", "Verdict Label", "Confidence Score", "Severity", "Classifier Tier", "Source Scenario"])
        for alert in alerts:
            writer.writerow([
                alert.id,
                alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                alert.predicted_label,
                f"{alert.confidence:.4f}",
                alert.severity,
                f"Tier {alert.tier}",
                alert.source_scenario
            ])
            
        output = BytesIO(csv_buffer.getvalue().encode('utf-8'))
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
        
    else: # pdf
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#4f46e5'),
            spaceAfter=15
        )
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=11,
            textColor=colors.HexColor('#1e1b4b'),
            spaceBefore=12,
            spaceAfter=6
        )
        normal_style = styles['Normal']
        
        elements = []
        elements.append(Paragraph("AI-Powered SOC Telemetry Incident Report", title_style))
        
        meta_info = (
            f"<b>Generated At:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            f"<b>Query Range:</b> {date_from.strftime('%Y-%m-%d %H:%M:%S') if date_from else 'All Time'} to {date_to.strftime('%Y-%m-%d %H:%M:%S') if date_to else 'Present'}<br/>"
            f"<b>Total Logged Threats:</b> {total_alerts}"
        )
        elements.append(Paragraph(meta_info, normal_style))
        elements.append(Spacer(1, 15))
        
        elements.append(Paragraph("Resolution Classification Tier Breakdown", section_style))
        tier_data = [
            ["Escalation Classifier Tier", "Alert Count", "Percentage of Total"],
            ["Tier 1 (LightGBM)", str(by_tier[1]), f"{(by_tier[1] / total_alerts * 100):.1f}%" if total_alerts else "0.0%"],
            ["Tier 2 (Random Forest)", str(by_tier[2]), f"{(by_tier[2] / total_alerts * 100):.1f}%" if total_alerts else "0.0%"],
            ["Tier 3 (Weighted Ensemble)", str(by_tier[3]), f"{(by_tier[3] / total_alerts * 100):.1f}%" if total_alerts else "0.0%"]
        ]
        t_tier = Table(tier_data, colWidths=[220, 140, 140])
        t_tier.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4f46e5')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
            ('PADDING', (0,1), (-1,-1), 5),
        ]))
        elements.append(t_tier)
        elements.append(Spacer(1, 15))
        
        elements.append(Paragraph("Incident Threat Category Summary", section_style))
        threat_data = [["Attack Type Category", "Frequency Count", "Percentage of Total"]]
        for label, cnt in by_attack.items():
            threat_data.append([
                label, str(cnt), f"{(cnt / total_alerts * 100):.1f}%" if total_alerts else "0.0%"
            ])
        if not by_attack:
            threat_data.append(["No security incidents logged.", "0", "0.0%"])
            
        t_threat = Table(threat_data, colWidths=[220, 140, 140])
        t_threat.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e1b4b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
            ('PADDING', (0,1), (-1,-1), 5),
        ]))
        elements.append(t_threat)
        elements.append(Spacer(1, 15))
        
        elements.append(Paragraph("Logged Incidents Log Feed (Latest 50 alerts)", section_style))
        feed_data = [["ID", "Timestamp (UTC)", "Verdict Label", "Conf", "Severity", "Tier", "Source Scenario"]]
        for alert in alerts[:50]:
            feed_data.append([
                str(alert.id),
                alert.timestamp.strftime('%H:%M:%S'),
                alert.predicted_label,
                f"{alert.confidence:.2%}",
                alert.severity,
                f"T{alert.tier}",
                alert.source_scenario
            ])
        if not alerts:
            feed_data.append(["-", "-", "No logged events.", "-", "-", "-", "-"])
            
        t_feed = Table(feed_data, colWidths=[30, 70, 110, 50, 60, 40, 140])
        t_feed.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,0), 4),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8fafc')),
            ('PADDING', (0,1), (-1,-1), 4),
        ]))
        elements.append(t_feed)
        
        if total_alerts > 50:
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<i>* Report shows latest 50 of {total_alerts} matching alerts. Export to CSV for full audit logs.</i>", styles['Italic']))
            
        doc.build(elements)
        buffer.seek(0)
        
        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"}
        )

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
