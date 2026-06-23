import time
from pathlib import Path
from app.config import settings
from app.data.loader import find_csv_files, safe_read_csv, clean_dataframe, load_dataset

def main():
    print("=" * 60)
    print("      CIC-IDS-2017 DATA INGESTION & CLEANING TOOL")
    print("=" * 60)
    
    raw_dir = Path(settings.DATA_RAW_DIR)
    print(f"Configured Raw Data Path: {raw_dir.absolute()}")
    
    if not raw_dir.exists():
        print(f"ERROR: Raw data path does not exist. Please check your configuration.")
        return
        
    start_time = time.time()
    
    # 1. Locate files
    try:
        csv_files = find_csv_files(raw_dir)
        if not csv_files:
            print(f"ERROR: No CSV files found in: {raw_dir}")
            return
    except Exception as e:
        print(f"ERROR locating CSV files: {e}")
        return
        
    print(f"Found {len(csv_files)} CSV files to process.")
    
    # 2. Process and track sizes
    total_original_rows = 0
    total_cleaned_rows = 0
    dfs = []
    
    for path in csv_files:
        print(f"\nProcessing: {path.name}")
        try:
            # Read
            df_raw = safe_read_csv(path)
            orig_rows = len(df_raw)
            total_original_rows += orig_rows
            print(f"  - Loaded {orig_rows:,} raw rows.")
            
            # Clean
            df_cleaned = clean_dataframe(df_raw, file_name=path.name)
            total_cleaned_rows += len(df_cleaned)
            
            if len(df_cleaned) > 0:
                dfs.append(df_cleaned)
        except Exception as e:
            print(f"  - ERROR processing {path.name}: {e}")
            
    if not dfs:
        print("\nERROR: No rows remained after cleaning!")
        return
        
    # 3. Concatenate
    print("\nConcatenating datasets...")
    combined_df = load_dataset(raw_dir) # Uses the module implementation to ensure consistency
    
    elapsed_time = time.time() - start_time
    
    # 4. Generate Ingestion Summary
    print("\n" + "=" * 60)
    print("               DATA INGESTION SUMMARY")
    print("=" * 60)
    print(f"Time Elapsed:         {elapsed_time:.2f} seconds")
    print(f"Total Raw Rows:       {total_original_rows:,}")
    print(f"Total Cleaned Rows:   {len(combined_df):,}")
    
    dropped_rows = total_original_rows - len(combined_df)
    dropped_percent = (dropped_rows / total_original_rows) * 100 if total_original_rows > 0 else 0
    print(f"Total Rows Dropped:   {dropped_rows:,} ({dropped_percent:.2f}%)")
    
    # Features count (columns except target 'Label')
    columns = list(combined_df.columns)
    feature_columns = [col for col in columns if col != "Label"]
    print(f"Total Columns:        {len(columns)}")
    print(f"Feature Count:        {len(feature_columns)}")
    
    print("\n" + "-" * 40)
    print("CLASS DISTRIBUTION PER ATTACK TYPE")
    print("-" * 40)
    
    # Calculate class counts and percentages
    class_counts = combined_df["Label"].value_counts()
    class_percentages = combined_df["Label"].value_counts(normalize=True) * 100
    
    print(f"{'Attack Label':<35} | {'Count':<10} | {'Percentage':<10}")
    print("-" * 63)
    for label, count in class_counts.items():
        pct = class_percentages[label]
        print(f"{label:<35} | {count:<10,} | {pct:.4f}%")
    print("=" * 60)

if __name__ == "__main__":
    main()
