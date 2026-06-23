import json
import logging
from pathlib import Path
import joblib
import numpy as np
from app.config import settings

logger = logging.getLogger(__name__)

class CascadeDetector:
    """Multi-tier inference cascade detector for cybersecurity threats.
    
    Escalation Logic:
      - Tier 1: LightGBM (Speed-tuned Fast Screener). If max probability >= threshold, return it.
      - Tier 2: Random Forest (Explainable Validator). If max probability >= threshold, return it.
      - Tier 3: XGBoost & Weighted Vote (Expert Ensemble). Uses a weighted probability vote across all three models.
    """
    
    def __init__(self, confidence_threshold: float = 0.85, weights: dict = None):
        """Initializes the detector and loads models + scalers + encoders once.
        
        Args:
            confidence_threshold (float): Default confidence threshold to trigger escalation.
            weights (dict): Weights for ensemble voting in Tier 3.
        """
        self.confidence_threshold = confidence_threshold
        self.weights = weights or {"lightgbm": 0.2, "random_forest": 0.3, "xgboost": 0.5}
        
        cache_dir = Path(settings.DATA_CACHE_DIR)
        model_dir = cache_dir / "models"
        
        scaler_path = cache_dir / "scaler.joblib"
        encoder_path = cache_dir / "label_encoder.joblib"
        features_path = cache_dir / "features.json"
        
        if not (scaler_path.exists() and encoder_path.exists() and features_path.exists()):
            raise FileNotFoundError("Cascade assets (scaler, encoder, or features list) are missing. Run prepare_data first.")
            
        logger.info("Loading ML Preprocessing Scaler and Encoders...")
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(encoder_path)
        
        with open(features_path, "r") as f:
            self.selected_features = json.load(f)
            
        models_to_load = {
            "lightgbm": model_dir / "lightgbm.joblib",
            "random_forest": model_dir / "random_forest.joblib",
            "xgboost": model_dir / "xgboost.joblib"
        }
        
        self.models = {}
        for name, path in models_to_load.items():
            if not path.exists():
                raise FileNotFoundError(f"Model file {path.name} not found. Run training script first.")
            logger.info(f"Loading {name} model into memory...")
            self.models[name] = joblib.load(path)
            
        logger.info("CascadeDetector initialized and all assets loaded.")
        
    def detect(self, features_dict: dict, threshold: float = None) -> dict:
        """Classifies a network packet flow using the 3-tier cascade and provides XAI explanations.
        
        Args:
            features_dict (dict): Raw feature mapping from packet flow.
            threshold (float): Confidence threshold to trigger escalation. Defaults to self.confidence_threshold.
            
        Returns:
            dict: containing:
              - predicted_label (str): Name of the predicted class (decoded).
              - confidence (float): Confidence score of the prediction.
              - tier (int): 1, 2, or 3.
              - tier_name (str): Readable name of the tier that resolved the request.
              - top_features (list): 3-5 most important features for this decision.
        """
        if threshold is None:
            threshold = self.confidence_threshold
            
        # 1. Align features with selected features list
        try:
            feature_vector = []
            for feat in self.selected_features:
                val = features_dict.get(feat, 0.0)
                feature_vector.append(float(val))
        except Exception as e:
            raise ValueError(f"Feature alignment failed: {e}. Check input feature names.")
            
        # 2. Scale features (expects 2D array)
        raw_vector = np.array(feature_vector).reshape(1, -1)
        scaled_vector = self.scaler.transform(raw_vector)
        
        # Convert to DataFrame to match training feature names and avoid scikit-learn warnings
        import pandas as pd
        scaled_df = pd.DataFrame(scaled_vector, columns=self.selected_features)
        
        # Helper to compute XAI explanations (based on Random Forest feature importances)
        def get_top_features(scaled_vec: np.ndarray, num_features: int = 4) -> list[dict]:
            rf_model = self.models["random_forest"]
            importances = rf_model.feature_importances_
            # Impact is calculated as scaled sample value * global feature importance
            impacts = scaled_vec[0] * importances
            
            # Sort by impact magnitude descending
            sorted_indices = np.argsort(np.abs(impacts))[::-1][:num_features]
            
            top_feats = []
            for idx in sorted_indices:
                feat_name = self.selected_features[idx]
                raw_val = float(features_dict.get(feat_name, 0.0))
                importance_val = float(importances[idx])
                impact_val = float(impacts[idx])
                
                top_feats.append({
                    "feature": feat_name,
                    "value": raw_val,
                    "importance": importance_val,
                    "impact": impact_val
                })
            return top_feats

        # --- Tier 1: LightGBM (Fast Screener) ---
        lgb_model = self.models["lightgbm"]
        lgb_probs = lgb_model.predict_proba(scaled_df)[0]
        lgb_class_idx = np.argmax(lgb_probs)
        lgb_conf = float(lgb_probs[lgb_class_idx])
        
        if lgb_conf >= threshold:
            predicted_class = self.label_encoder.inverse_transform([lgb_class_idx])[0]
            return {
                "predicted_label": str(predicted_class),
                "confidence": lgb_conf,
                "tier": 1,
                "tier_name": "Tier 1: LightGBM (Fast Screener)",
                "top_features": get_top_features(scaled_vector)
            }
            
        # --- Tier 2: Random Forest (Explainable Validator) ---
        rf_model = self.models["random_forest"]
        rf_probs = rf_model.predict_proba(scaled_df)[0]
        rf_class_idx = np.argmax(rf_probs)
        rf_conf = float(rf_probs[rf_class_idx])
        
        if rf_conf >= threshold:
            predicted_class = self.label_encoder.inverse_transform([rf_class_idx])[0]
            return {
                "predicted_label": str(predicted_class),
                "confidence": rf_conf,
                "tier": 2,
                "tier_name": "Tier 2: Random Forest (Explainable Validator)",
                "top_features": get_top_features(scaled_vector)
            }
            
        # --- Tier 3: XGBoost & Weighted Vote (Expert Ensemble) ---
        xgb_model = self.models["xgboost"]
        xgb_probs = xgb_model.predict_proba(scaled_df)[0]
        
        # Weighted Vote calculation
        w_lgb = self.weights.get("lightgbm", 0.2)
        w_rf = self.weights.get("random_forest", 0.3)
        w_xgb = self.weights.get("xgboost", 0.5)
        
        weighted_probs = (w_lgb * lgb_probs) + (w_rf * rf_probs) + (w_xgb * xgb_probs)
        final_class_idx = np.argmax(weighted_probs)
        final_conf = float(weighted_probs[final_class_idx])
        
        predicted_class = self.label_encoder.inverse_transform([final_class_idx])[0]
        return {
            "predicted_label": str(predicted_class),
            "confidence": final_conf,
            "tier": 3,
            "tier_name": "Tier 3: XGBoost (Weighted Cascade Vote)",
            "top_features": get_top_features(scaled_vector)
        }

# Singletons to cache loaded assets in memory for backward compatibility
_detector_instance = None

def load_cascade_assets():
    """Backward compatible loader that initializes the global detector singleton."""
    get_detector()

def get_detector() -> CascadeDetector:
    """Helper to initialize or retrieve a global singleton instance of CascadeDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = CascadeDetector()
    return _detector_instance

def predict_cascade(features_dict: dict, confidence_threshold: float = 0.85) -> dict:
    """Classifies a network packet flow using the 3-tier cascade and provides XAI explanations.
    
    This function remains backward compatible with existing references.
    """
    detector = get_detector()
    result = detector.detect(features_dict, threshold=confidence_threshold)
    # Map top_features back to explanation for backwards compatibility
    result["explanation"] = result["top_features"]
    return result

if __name__ == "__main__":
    # Configure self-test logs
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    
    print("=" * 80)
    print("                  CASCADE DETECTOR SELF-TEST REPORT")
    print("=" * 80)
    
    explanation_text = """
    ESCALATION AND WEIGHTED VOTE CASCADE DESIGN:
    
    1. Tier 1 (LightGBM - Speed-tuned Fast Screener):
       LightGBM is highly efficient and offers high accuracy. If its prediction confidence
       (maximum class probability) is >= threshold (default 0.85), the prediction is accepted.
       This resolves standard, unambiguous flows immediately without hitting slower models.
       
    2. Tier 2 (Random Forest - Explainable Validator):
       If Tier 1 fails to meet the confidence threshold, the flow is escalated to Random Forest.
       If Tier 2 confidence is >= threshold, the decision is resolved here.
       
    3. Tier 3 (XGBoost & Weighted Vote - Expert Ensemble):
       If both Tier 1 and Tier 2 fail to reach the threshold, we execute XGBoost and compute
       a weighted probability vote across all three models:
         Combined Probability = 0.2 * LGBM_Prob + 0.3 * RF_Prob + 0.5 * XGBoost_Prob
       The class with the highest combined probability wins. This handles ambiguous borderline
       cases using the consensus of all three classifiers.
    """
    print(explanation_text)
    print("-" * 80)
    
    try:
        # Initialize detector
        detector = CascadeDetector()
        
        # Load cache to fetch raw samples
        cache_dir = Path(settings.DATA_CACHE_DIR)
        npz_path = cache_dir / "processed_data.npz"
        
        if not npz_path.exists():
            print(f"Error: Processed dataset npz file {npz_path} is missing. Please run prepare_data_run.py first.")
        else:
            print("Loading test samples from cache for self-test...")
            with np.load(npz_path) as data:
                X_test = data["X_test"]
                y_test = data["y_test"]
            
            # Select first 5 samples from unique classes in the test set to show diversity
            unique_labels, first_indices = np.unique(y_test, return_index=True)
            test_indices = list(first_indices[:5])
            
            # Reconstruct raw inputs using inverse scaler
            unscaled_X_test = detector.scaler.inverse_transform(X_test[test_indices])
            
            for idx_rank, test_idx in enumerate(test_indices):
                raw_row = unscaled_X_test[idx_rank]
                true_class_idx = y_test[test_idx]
                true_label = detector.label_encoder.inverse_transform([true_class_idx])[0]
                
                # Build dict mapping feature names to raw values
                flow_dict = dict(zip(detector.selected_features, raw_row))
                
                # Test with default threshold (0.85) and strict threshold (0.99) to force escalation
                for threshold_val in [0.85, 0.99]:
                    print(f"\n---> Testing Test Sample #{test_idx} | True Label: {true_label} | Threshold: {threshold_val}")
                    result = detector.detect(flow_dict, threshold=threshold_val)
                    print(f"     Predicted Label: {result['predicted_label']}")
                    print(f"     Confidence:      {result['confidence']:.6f}")
                    print(f"     Resolved Tier:   {result['tier_name']} (Tier {result['tier']})")
                    print("     Local Feature Explanations (Top Attributions):")
                    for i, feat in enumerate(result['top_features']):
                        print(
                            f"       {i+1}. {feat['feature']:<25} | "
                            f"Value: {feat['value']:<10.2f} | "
                            f"RF Importance: {feat['importance']:.5f} | "
                            f"Impact Score: {feat['impact']:.5f}"
                        )
                        
    except Exception as e:
        print(f"\nSelf-test failed: {e}")
        import traceback
        traceback.print_exc()
        
    print("=" * 80)
