import logging
from pathlib import Path
import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def safe_read_csv(file_path: Path) -> pd.DataFrame:
    """Reads a CSV file, falling back to latin-1 encoding if utf-8 fails.
    
    Args:
        file_path (Path): Path to the CSV file.
        
    Returns:
        pd.DataFrame: Loaded pandas DataFrame.
    """
    try:
        logger.debug(f"Attempting to read {file_path.name} with UTF-8 encoding")
        return pd.read_csv(file_path, encoding="utf-8")
    except UnicodeDecodeError:
        logger.warning(f"UTF-8 decode failed for {file_path.name}. Retrying with latin-1 fallback.")
        return pd.read_csv(file_path, encoding="latin-1")

def clean_dataframe(df: pd.DataFrame, file_name: str = "") -> pd.DataFrame:
    """Cleans a DataFrame loaded from CIC-IDS-2017 CSV file.
    
    Cleaning steps:
      - Strips whitespace from column names.
      - Standardizes label column name to 'Label'.
      - Drops fully-empty padding rows (e.g. blank rows).
      - Drops any row that has more than 50 NaN features.
      - Replaces positive/negative infinities with NaN.
      - Drops any rows that still contain NaNs (justification in implementation plan).
      
    Args:
        df (pd.DataFrame): Input raw DataFrame.
        file_name (str): Optional name of the file for logging context.
        
    Returns:
        pd.DataFrame: Cleaned DataFrame.
    """
    initial_rows = len(df)
    
    # 1. Strip column names and rename label column
    df.columns = df.columns.str.strip()
    rename_dict = {col: "Label" for col in df.columns if col.lower() == "label"}
    if rename_dict:
        df = df.rename(columns=rename_dict)
        
    # Clean label values to remove whitespace and non-ASCII characters (e.g. \x96 en-dash)
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip().str.replace("\x96", "-", regex=False)
    
    # 2. Drop fully empty rows
    df = df.dropna(how="all")
    rows_after_empty_drop = len(df)
    empty_dropped = initial_rows - rows_after_empty_drop
    if empty_dropped > 0:
        logger.info(f"[{file_name}] Dropped {empty_dropped:,} fully-empty rows.")

    # 3. Drop rows with > 50 NaN features
    # (requires that the row has at least [number of columns - 50] non-NaN values)
    col_count = len(df.columns)
    min_non_nan = max(0, col_count - 50)
    df = df.dropna(thresh=min_non_nan)
    rows_after_high_nan_drop = len(df)
    high_nan_dropped = rows_after_empty_drop - rows_after_high_nan_drop
    if high_nan_dropped > 0:
        logger.info(f"[{file_name}] Dropped {high_nan_dropped:,} rows containing > 50 NaN features.")

    # 4. Replace infinities (+/-) with NaN
    # We replace np.inf and -np.inf across all features
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_count = 0
    if len(numeric_cols) > 0:
        # Count inf values before replacing
        inf_mask = np.isinf(df[numeric_cols])
        inf_count = inf_mask.sum().sum()
        if inf_count > 0:
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
            logger.info(f"[{file_name}] Replaced {inf_count:,} positive/negative infinity values with NaN.")

    # 5. Handle remaining NaNs by dropping them
    # Justification: The rows containing NaN features represent an extremely small percentage of 
    # the dataset (< 0.1%). Dropping them preserves clean network metrics without introducing 
    # synthetic noise that could impact machine learning accuracy.
    rows_before_final_nan = len(df)
    df = df.dropna()
    rows_after_final_nan = len(df)
    final_nan_dropped = rows_before_final_nan - rows_after_final_nan
    if final_nan_dropped > 0:
        logger.info(f"[{file_name}] Dropped {final_nan_dropped:,} rows containing remaining NaN values.")

    logger.info(
        f"[{file_name}] Cleaned: {initial_rows:,} -> {len(df):,} rows "
        f"({initial_rows - len(df):,} rows dropped in total)."
    )
    return df

def find_csv_files(data_dir: Path) -> list[Path]:
    """Finds target TrafficLabelling CSV files in raw data path.
    
    Args:
        data_dir (Path): Base raw data directory.
        
    Returns:
        list[Path]: List of CSV file paths.
    """
    # Standard subfolder search
    standard_sub = data_dir / "CIC-IDS-2017" / "CSVs" / "TrafficLabelling"
    if standard_sub.exists() and standard_sub.is_dir():
        logger.info(f"Detected standard TrafficLabelling subfolder: {standard_sub}")
        csv_files = list(standard_sub.glob("*.csv"))
        if csv_files:
            return csv_files
            
    # Fallback recursive search
    logger.info(f"Searching recursively for CSV files in {data_dir}")
    all_csvs = list(data_dir.glob("**/*.csv"))
    
    # Filter to TrafficLabelling style names
    traffic_csvs = [
        f for f in all_csvs 
        if "workinghours" in f.name.lower() or "pcap_iscx.csv" in f.name.lower()
    ]
    
    if traffic_csvs:
        logger.info(f"Found {len(traffic_csvs)} TrafficLabelling CSVs via recursive naming match.")
        return traffic_csvs
        
    logger.warning(f"Could not find specific TrafficLabelling CSV matches. Returning all {len(all_csvs)} CSVs.")
    return all_csvs

def load_dataset(data_dir: Path) -> pd.DataFrame:
    """Finds, safe-reads, cleans, and concatenates all 8 TrafficLabelling CSV files.
    
    Args:
        data_dir (Path): Base raw data directory.
        
    Returns:
        pd.DataFrame: Combined and cleaned dataset.
    """
    csv_paths = find_csv_files(data_dir)
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in raw data directory: {data_dir}")
        
    logger.info(f"Found {len(csv_paths)} CSV files to load: {[p.name for p in csv_paths]}")
    
    dfs = []
    for path in csv_paths:
        logger.info(f"Loading file: {path.name}")
        df = safe_read_csv(path)
        cleaned_df = clean_dataframe(df, file_name=path.name)
        
        # Only add non-empty DataFrames
        if len(cleaned_df) > 0:
            dfs.append(cleaned_df)
            
    if not dfs:
        raise ValueError("All loaded DataFrames are empty after cleaning!")
        
    logger.info("Concatenating all datasets...")
    combined_df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Dataset concatenation complete. Total combined rows: {len(combined_df):,}")
    
    return combined_df

def prepare_data(force: bool = False, top_k: int = 30) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Loads, processes, performs feature selection, applies SMOTE, scales, and caches dataset splits.
    
    Args:
        force (bool): If True, re-runs the entire pipeline even if cached files exist.
        top_k (int): Number of top features to select using Random Forest.
        
    Returns:
        tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]: X_train, X_test, y_train, y_test arrays.
    """
    import json
    import joblib
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    from imblearn.over_sampling import SMOTE
    from app.config import settings

    cache_dir = Path(settings.DATA_CACHE_DIR)
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    npz_path = cache_dir / "processed_data.npz"
    encoder_path = cache_dir / "label_encoder.joblib"
    scaler_path = cache_dir / "scaler.joblib"
    features_path = cache_dir / "features.json"
    smote_stats_path = cache_dir / "smote_stats.json"
    
    cached_files = [npz_path, encoder_path, scaler_path, features_path, smote_stats_path]
    all_cached = all(f.exists() for f in cached_files)
    
    if all_cached and not force:
        logger.info("Found all cached preprocessed files. Loading from cache...")
        with np.load(npz_path) as data:
            X_train = data["X_train"]
            X_test = data["X_test"]
            y_train = data["y_train"]
            y_test = data["y_test"]
        logger.info(f"Loaded train/test splits from cache: X_train shape={X_train.shape}, X_test shape={X_test.shape}")
        return X_train, X_test, y_train, y_test

    logger.info("Cache missed or force=True. Starting dataset preprocessing pipeline...")
    
    # 1. Load the cleaned dataframe
    raw_dir = Path(settings.DATA_RAW_DIR)
    df = load_dataset(raw_dir)
    
    # 2. DROP identifier columns that cause leakage
    leakage_cols = ["Flow ID", "Source IP", "Destination IP", "Source Port", "Destination Port", "Timestamp"]
    drop_cols = [col for col in leakage_cols if col in df.columns]
    if drop_cols:
        logger.info(f"Dropping leak-causing identifier columns: {drop_cols}")
        df = df.drop(columns=drop_cols)
        
    # Split into features (X) and target (y)
    if "Label" not in df.columns:
        raise ValueError("Standardized 'Label' column is missing from the dataset!")
        
    X = df.drop(columns=["Label"])
    y = df["Label"]
    
    # 3. Label-encode the target and SAVE the encoder
    logger.info("Label-encoding the target labels...")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    joblib.dump(label_encoder, encoder_path)
    logger.info(f"Saved label encoder to: {encoder_path}")
    
    # 4. Stratified 80/20 train/test split
    logger.info("Splitting dataset into 80/20 train/test splits (stratified)...")
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
    )
    
    # 5. Feature selection by Random Forest importance (on subsample)
    logger.info("Selecting top features using Random Forest importance...")
    subsample_size = min(100000, len(X_train_raw))
    
    # Create a stratified subsample of X_train_raw for feature selection
    _, X_sub, _, y_sub = train_test_split(
        X_train_raw, y_train, test_size=subsample_size, stratify=y_train, random_state=42
    )
    
    logger.info(f"Fitting Random Forest classifier on stratified subsample of {subsample_size:,} rows...")
    rf = RandomForestClassifier(n_estimators=50, max_depth=12, n_jobs=-1, random_state=42)
    rf.fit(X_sub, y_sub)
    
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    top_indices = indices[:top_k]
    selected_features = list(X.columns[top_indices])
    
    # Save selected features to features.json
    with open(features_path, "w") as f:
        json.dump(selected_features, f, indent=2)
    logger.info(f"Saved top-{top_k} selected features list to: {features_path}")
    logger.info(f"Selected features: {selected_features}")
    
    # Filter features
    X_train_filtered = X_train_raw[selected_features].values
    X_test_filtered = X_test_raw[selected_features].values
    
    # 6. Apply SMOTE to the TRAINING set ONLY
    logger.info("Applying SMOTE oversampling to the training set...")
    
    # Calculate class distribution before SMOTE
    unique_labels, count_before = np.unique(y_train, return_counts=True)
    classes_before = {label_encoder.inverse_transform([lbl])[0]: int(cnt) for lbl, cnt in zip(unique_labels, count_before)}
    
    # Dynamic neighbor threshold to avoid crashing on tiny classes
    min_class_count = int(np.min(count_before))
    k_neighbors = min(5, min_class_count - 1)
    
    if k_neighbors < 1:
        k_neighbors = 1
        logger.warning(
            f"Extremely small minority class detected (min size = {min_class_count}). "
            f"Setting SMOTE k_neighbors=1."
        )
    else:
        logger.info(f"Setting SMOTE k_neighbors={k_neighbors} based on minimum class count of {min_class_count}")
        
    smote = SMOTE(k_neighbors=k_neighbors, random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train_filtered, y_train)
    
    # Calculate class distribution after SMOTE
    unique_labels_after, count_after = np.unique(y_train_resampled, return_counts=True)
    classes_after = {label_encoder.inverse_transform([lbl])[0]: int(cnt) for lbl, cnt in zip(unique_labels_after, count_after)}
    
    smote_stats = {
        "before_smote": classes_before,
        "after_smote": classes_after
    }
    with open(smote_stats_path, "w") as f:
        json.dump(smote_stats, f, indent=2)
    logger.info(f"Saved SMOTE stats to: {smote_stats_path}")
    
    # 7. StandardScaler
    logger.info("Applying standard scaling on features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_resampled)
    X_test_scaled = scaler.transform(X_test_filtered)
    
    joblib.dump(scaler, scaler_path)
    logger.info(f"Saved scaler to: {scaler_path}")
    
    # 8. Save processed splits to processed_data.npz
    logger.info("Saving preprocessed splits to compressed NPZ archive...")
    np.savez_compressed(
        npz_path,
        X_train=X_train_scaled,
        X_test=X_test_scaled,
        y_train=y_train_resampled,
        y_test=y_test
    )
    logger.info(f"Saved preprocessed data to: {npz_path}")
    
    return X_train_scaled, X_test_scaled, y_train_resampled, y_test
