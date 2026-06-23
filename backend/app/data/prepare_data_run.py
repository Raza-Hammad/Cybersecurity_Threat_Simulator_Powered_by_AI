import argparse
import json
import time
from pathlib import Path
import joblib
import numpy as np
from app.config import settings
from app.data.loader import prepare_data

def main():
    parser = argparse.ArgumentParser(description="ML Pipeline Preprocessing Runner")
    parser.add_argument("--force", action="store_true", help="Force execution and bypass cache")
    parser.add_argument("--top-k", type=int, default=30, help="Number of features to select")
    args = parser.parse_args()
    
    print("=" * 60)
    print("       CIC-IDS-2017 PREPROCESSING & SPLITTING PIPELINE")
    print("=" * 60)
    print(f"Force Re-Run:        {args.force}")
    print(f"Top-K Features:      {args.top_k}")
    print(f"Cache Location:      {Path(settings.DATA_CACHE_DIR).absolute()}")
    
    start_time = time.time()
    
    # Run pipeline
    try:
        X_train, X_test, y_train, y_test = prepare_data(force=args.force, top_k=args.top_k)
    except Exception as e:
        print(f"\nERROR running preprocessing pipeline: {e}")
        import traceback
        traceback.print_exc()
        return
        
    elapsed = time.time() - start_time
    
    # Load and print caching metadata details
    cache_dir = Path(settings.DATA_CACHE_DIR)
    features_path = cache_dir / "features.json"
    smote_stats_path = cache_dir / "smote_stats.json"
    encoder_path = cache_dir / "label_encoder.joblib"
    
    print("\n" + "=" * 60)
    print("                PIPELINE EXECUTION SUMMARY")
    print("=" * 60)
    print(f"Time Taken:           {elapsed:.2f} seconds")
    print(f"X_train shape:        {X_train.shape} (scaled)")
    print(f"y_train shape:        {y_train.shape} (resampled via SMOTE)")
    print(f"X_test shape:         {X_test.shape} (scaled)")
    print(f"y_test shape:         {y_test.shape} (original ratio)")
    
    # Print selected features
    if features_path.exists():
        with open(features_path, "r") as f:
            selected_features = json.load(f)
        print(f"\nSelected Top-{len(selected_features)} Features (Random Forest importance):")
        for i, feat in enumerate(selected_features, 1):
            print(f"  {i:<2}. {feat}")
            
    # Print SMOTE Oversampling Stats
    if smote_stats_path.exists() and encoder_path.exists():
        with open(smote_stats_path, "r") as f:
            smote_stats = json.load(f)
            
        print("\n" + "-" * 55)
        print("   SMOTE OVERSAMPLING CLASS COMPARISON (TRAINING SET)")
        print("-" * 55)
        print(f"{'Attack Class Label':<30} | {'Before SMOTE':<12} | {'After SMOTE':<12}")
        print("-" * 55)
        
        before = smote_stats.get("before_smote", {})
        after = smote_stats.get("after_smote", {})
        
        # Sort by count before SMOTE descending
        sorted_labels = sorted(before.keys(), key=lambda k: before[k], reverse=True)
        
        for label in sorted_labels:
            cnt_before = before.get(label, 0)
            cnt_after = after.get(label, 0)
            print(f"{label:<30} | {cnt_before:<12,} | {cnt_after:<12,}")
        print("=" * 60)
        
        # Check encoder classes
        encoder = joblib.load(encoder_path)
        print(f"\nTotal encoded target classes: {len(encoder.classes_)}")

if __name__ == "__main__":
    main()
