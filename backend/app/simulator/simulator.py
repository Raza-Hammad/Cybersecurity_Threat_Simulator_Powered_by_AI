import asyncio
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
import json
from sqlmodel import Session

from app.config import settings
from app.db import engine, Alert
from app.ml.cascade import get_detector

logger = logging.getLogger(__name__)

class SimulationEngine:
    """Safely simulates network traffic threat streams by replaying CIC-IDS2017 test dataset rows."""
    def __init__(self):
        self.is_running = False
        self.current_scenario = None
        self.packets_sent = 0
        self.attacks_detected = 0
        self.tier_breakdown = {1: 0, 2: 0, 3: 0}
        self.rate = 1  # packets per second
        self.duration_seconds = None
        self.start_time = None
        
        self.task = None
        
        # Test dataset arrays & metadata
        self.X_test = None
        self.y_test = None
        self.label_to_indices = {}
        self.scenarios = {}
        self.all_attack_indices = None
        self.selected_features = None
        self.scaler = None
        self.classes = None
        self.is_initialized = False

    def initialize(self):
        """Pre-loads and maps row indices of the prepared test dataset by target label."""
        if self.is_initialized:
            return
            
        logger.info("Initializing SimulationEngine...")
        try:
            # Retrieve scaler, encoders and features from the CascadeDetector singleton
            detector = get_detector()
            self.selected_features = detector.selected_features
            self.scaler = detector.scaler
            self.classes = detector.label_encoder.classes_
            
            npz_path = Path(settings.DATA_CACHE_DIR) / "processed_data.npz"
            if not npz_path.exists():
                raise FileNotFoundError(f"Prepared test dataset NPZ file not found at {npz_path}. Run prepare_data first.")
                
            logger.info("Memory mapping test dataset splits...")
            data = np.load(npz_path, mmap_mode="r")
            self.X_test = data["X_test"]
            self.y_test = data["y_test"]
            
            # Map labels to their matching test set indices using fast NumPy operations
            for class_idx, label_name in enumerate(self.classes):
                self.label_to_indices[label_name] = np.where(self.y_test == class_idx)[0]
                logger.info(f"Scenario mapping: Found {len(self.label_to_indices[label_name])} samples for '{label_name}'")
            
            # Group classes into scenario presets
            self.scenarios = {
                "benign_baseline": self.label_to_indices.get("BENIGN", np.array([])),
                "ddos_storm": np.concatenate([
                    self.label_to_indices.get(lbl, np.array([]))
                    for lbl in ["DDoS", "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest"]
                    if lbl in self.label_to_indices
                ]),
                "port_scan": self.label_to_indices.get("PortScan", np.array([])),
                "brute_force": np.concatenate([
                    self.label_to_indices.get(lbl, np.array([]))
                    for lbl in ["FTP-Patator", "SSH-Patator", "Web Attack - Brute Force"]
                    if lbl in self.label_to_indices
                ]),
            }
            
            # Index of BENIGN class to distinguish attacks in mixed scenario
            benign_class_idx = list(self.classes).index("BENIGN")
            self.all_attack_indices = np.where(self.y_test != benign_class_idx)[0]
            
            for preset_name, indices in self.scenarios.items():
                logger.info(f"Scenario preset '{preset_name}' mapped to {len(indices)} threat rows.")
                
            self.is_initialized = True
            logger.info("SimulationEngine successfully initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize SimulationEngine index cache: {e}")
            raise e

    def start(self, scenario: str, rate: int, duration_seconds: int = None):
        """Starts the simulator streaming task in the background."""
        if not self.is_initialized:
            self.initialize()
            
        if self.is_running:
            raise ValueError("Simulation is already running. Stop it first.")
            
        valid_scenarios = ["ddos_storm", "port_scan", "brute_force", "mixed_attack", "benign_baseline"]
        if scenario not in valid_scenarios:
            raise ValueError(f"Invalid scenario name: {scenario}. Must be one of {valid_scenarios}")
            
        self.is_running = True
        self.current_scenario = scenario
        self.rate = rate
        self.duration_seconds = duration_seconds
        self.packets_sent = 0
        self.attacks_detected = 0
        self.tier_breakdown = {1: 0, 2: 0, 3: 0}
        self.start_time = datetime.utcnow()
        
        logger.info(f"Launching background simulation task. Scenario: {scenario}, Rate: {rate} packets/sec, Duration: {duration_seconds}s")
        self.task = asyncio.create_task(self._runner())

    def stop(self):
        """Stops the active streaming background task."""
        if not self.is_running:
            return
            
        logger.info("Cancelling simulation background worker task...")
        self.is_running = False
        if self.task:
            self.task.cancel()
            self.task = None
        logger.info("Simulation background task cleanly stopped.")

    def get_status(self) -> dict:
        """Returns active simulator telemetry and counters."""
        elapsed = 0
        if self.is_running and self.start_time:
            elapsed = (datetime.utcnow() - self.start_time).total_seconds()
            
        return {
            "running": self.is_running,
            "scenario": self.current_scenario,
            "rate": self.rate,
            "duration_seconds": self.duration_seconds,
            "elapsed_seconds": int(elapsed),
            "packets_sent": self.packets_sent,
            "attacks_detected": self.attacks_detected,
            "tier_breakdown": self.tier_breakdown
        }

    async def _runner(self):
        """Background loop streaming dataset rows through ML cascade and WebSocket."""
        try:
            detector = get_detector()
            
            # Import dynamically to avoid circular imports during module load
            from app.main import broadcast_detection
            
            interval = 1.0 / self.rate
            
            while self.is_running:
                # 1. Select index list matching scenario
                if self.current_scenario == "mixed_attack":
                    # Mixed attack: 20% BENIGN, 80% randomly selected from any attack class
                    if np.random.rand() < 0.20:
                        source_indices = self.scenarios["benign_baseline"]
                    else:
                        source_indices = self.all_attack_indices
                else:
                    source_indices = self.scenarios.get(self.current_scenario, np.array([]))
                    
                if len(source_indices) == 0:
                    logger.warning(f"No source rows found for scenario '{self.current_scenario}'. Replaying benign baseline.")
                    source_indices = self.scenarios["benign_baseline"]
                    
                # 2. Pick a random row index with replacement
                idx = int(np.random.choice(source_indices))
                
                # 3. Extract scaled vector and unscale to reconstruct human-readable values
                scaled_row = self.X_test[idx]
                unscaled_row = self.scaler.inverse_transform(scaled_row.reshape(1, -1))[0]
                features_dict = {
                    name: float(val) for name, val in zip(self.selected_features, unscaled_row)
                }
                
                # 4. Classify using CascadeDetector
                result = detector.detect(features_dict)
                predicted_label = result["predicted_label"]
                confidence = result["confidence"]
                tier = result["tier"]
                
                # 5. Persist non-benign threat predictions as SQLModel Alerts
                if predicted_label.upper() != "BENIGN":
                    try:
                        with Session(engine) as session:
                            alert = Alert(
                                predicted_label=predicted_label,
                                confidence=confidence,
                                tier=tier,
                                source_scenario=self.current_scenario,
                                raw_features=json.dumps(features_dict)
                            )
                            session.add(alert)
                            session.commit()
                            session.refresh(alert)
                            # Append IDs for frontend display
                            result["alert_id"] = alert.id
                            result["source_scenario"] = alert.source_scenario
                    except Exception as db_err:
                        logger.error(f"Error persisting simulator alert: {db_err}")
                
                # 6. Broadcast packet details over /ws/live to all clients
                try:
                    await broadcast_detection(result)
                except Exception as ws_err:
                    logger.warning(f"WebSocket streaming error during simulation: {ws_err}")
                
                # Update runner telemetry state
                self.packets_sent += 1
                if predicted_label.upper() != "BENIGN":
                    self.attacks_detected += 1
                self.tier_breakdown[tier] = self.tier_breakdown.get(tier, 0) + 1
                
                # Check duration completion
                if self.duration_seconds and self.start_time:
                    elapsed = (datetime.utcnow() - self.start_time).total_seconds()
                    if elapsed >= self.duration_seconds:
                        logger.info(f"Simulation completed. Duration limit of {self.duration_seconds}s reached.")
                        self.is_running = False
                        break
                        
                await asyncio.sleep(interval)
                
        except asyncio.CancelledError:
            logger.info("Simulation runner loop cancelled.")
        except Exception as e:
            logger.error(f"Critical error in simulator streaming loop: {e}")
        finally:
            self.is_running = False

# Global singleton instance
simulator_engine = SimulationEngine()
