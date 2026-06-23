import argparse
import json
import logging
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from sklearn.model_selection import train_test_split
from app.config import settings
from app.data.loader import prepare_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Try importing plotting libraries
try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    logger.warning("matplotlib or seaborn not installed. Heatmap PNG generation will be skipped.")

def plot_confusion_matrix(cm: np.ndarray, labels: list[str], output_path: Path, title: str):
    """Saves a confusion matrix heatmap as a PNG image."""
    if not PLOTTING_AVAILABLE:
        return
        
    plt.figure(figsize=(12, 10))
    sns.heatmap(
        cm, 
        annot=False,  # Set to False to keep heatmap clean since we have 15 classes
        cmap="Purples", 
        xticklabels=labels, 
        yticklabels=labels
    )
    plt.title(title, fontsize=14, fontweight="bold", pad=15)
    plt.ylabel("Actual Label", fontsize=12)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.xticks(rotation=45, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    logger.info(f"Saved confusion matrix plot to: {output_path}")

def train_all_models(force: bool = False, max_train_samples: int = 750000):
    """Loads cache, fits LightGBM, RF, and XGBoost, saves models, and evaluates metrics."""
    model_dir = Path(settings.DATA_CACHE_DIR) / "models"
    metrics_dir = Path(settings.DATA_CACHE_DIR) / "metrics"
    model_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    
    lgb_path = model_dir / "lightgbm.joblib"
    rf_path = model_dir / "random_forest.joblib"
    xgb_path = model_dir / "xgboost.joblib"
    summary_path = metrics_dir / "summary.json"
    encoder_path = Path(settings.DATA_CACHE_DIR) / "label_encoder.joblib"
    
    # Check if models already exist and force is False
    all_models_exist = lgb_path.exists() and rf_path.exists() and xgb_path.exists() and summary_path.exists()
    if all_models_exist and not force:
        logger.info("All models and metrics are already trained and cached. Skipping training.")
        with open(summary_path, "r") as f:
            summary = json.load(f)
        print_comparison_table(summary)
        return
        
    if not encoder_path.exists():
        raise FileNotFoundError("Label encoder not found in cache. Run prepare_data first.")
    label_encoder = joblib.load(encoder_path)
    class_labels = list(label_encoder.classes_)
    
    # Load dataset splits from cache
    logger.info("Loading preprocessed training and testing splits from cache...")
    X_train, X_test, y_train, y_test = prepare_data(force=False)
    
    # Subsampling the balanced training data if it exceeds the limit
    if len(X_train) > max_train_samples:
        logger.info(f"Subsampling training split from {len(X_train):,} to {max_train_samples:,} rows...")
        _, X_train, _, y_train = train_test_split(
            X_train, y_train, test_size=max_train_samples, stratify=y_train, random_state=42
        )
        logger.info(f"New training split shape: {X_train.shape}")
        
    # Lazy imports of model classes to keep import times fast
    from lightgbm import LGBMClassifier
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    
    models = {
        "LightGBM": LGBMClassifier(n_estimators=100, num_leaves=31, random_state=42, n_jobs=-1),
        "Random Forest": RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1)
    }
    
    summary = {}
    
    for name, clf in models.items():
        logger.info(f"\n--- Training {name} Model ---")
        
        # Fit model & measure time
        start_train = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - start_train
        logger.info(f"Finished training {name} in {train_time:.2f} seconds.")
        
        # Save model binary
        save_path = model_dir / f"{name.lower().replace(' ', '_')}.joblib"
        joblib.dump(clf, save_path)
        logger.info(f"Saved model to: {save_path}")
        
        # Inference speed & prediction test on untouched test set
        logger.info(f"Evaluating {name} on untouched test set ({len(X_test):,} rows)...")
        start_inf = time.time()
        y_pred = clf.predict(X_test)
        inf_time = time.time() - start_inf
        avg_inf_latency = (inf_time / len(X_test)) * 1000  # Latency in ms per sample
        logger.info(f"Average inference latency: {avg_inf_latency:.6f} ms/sample.")
        
        # Compute metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
        
        # Per-class F1 score
        per_class_precision, per_class_recall, per_class_f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average=None, labels=range(len(class_labels)), zero_division=0
        )
        
        per_class_f1_dict = {
            class_labels[i]: float(per_class_f1[i]) for i in range(len(class_labels))
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred, labels=range(len(class_labels)))
        
        # Save confusion matrix to JSON
        cm_json_path = metrics_dir / f"{name.lower().replace(' ', '_')}_conf_matrix.json"
        with open(cm_json_path, "w") as f:
            json.dump(cm.tolist(), f)
            
        # Save confusion matrix as PNG
        if PLOTTING_AVAILABLE:
            cm_png_path = metrics_dir / f"{name.lower().replace(' ', '_')}_conf_matrix.png"
            plot_confusion_matrix(cm, class_labels, cm_png_path, f"{name} Confusion Matrix")
            
        summary[name] = {
            "accuracy": float(accuracy),
            "macro_precision": float(precision),
            "macro_recall": float(recall),
            "macro_f1": float(f1),
            "training_time_seconds": float(train_time),
            "avg_inference_latency_ms": float(avg_inf_latency),
            "per_class_f1": per_class_f1_dict
        }
        
    # Save overall summary metrics
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Saved summary metrics to: {summary_path}")
    
    print_comparison_table(summary)

def print_comparison_table(summary: dict):
    """Helper to render a clean comparison table of the models in the console."""
    print("\n" + "=" * 80)
    print("                      ML MODEL COMPARISON REPORT")
    print("=" * 80)
    print(f"{'Model Name':<15} | {'Accuracy':<10} | {'Macro F1':<10} | {'Train Time (s)':<15} | {'Inf Latency (ms)':<17}")
    print("-" * 80)
    for name, metrics in summary.items():
        print(
            f"{name:<15} | "
            f"{metrics['accuracy']:<10.5f} | "
            f"{metrics['macro_f1']:<10.5f} | "
            f"{metrics['training_time_seconds']:<15.2f} | "
            f"{metrics['avg_inference_latency_ms']:<17.6f}"
        )
    print("=" * 80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ML Model Training Runner")
    parser.add_argument("--force", action="store_true", help="Force retraining of all models")
    parser.add_argument("--subsample-size", type=int, default=750000, help="Max balanced training rows")
    args = parser.parse_args()
    
    train_all_models(force=args.force, max_train_samples=args.subsample_size)
