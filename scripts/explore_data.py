"""
Data exploration script: analyze each CSV in datasets/ and report shape, columns, and label distribution.
Run: python scripts/explore_data.py
"""
import os
import pandas as pd

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets")

def explore_csv(name, path, nrows=None):
    print(f"\n{'='*60}")
    print(f"FILE: {name}")
    print(f"{'='*60}")
    try:
        if nrows:
            df = pd.read_csv(path, nrows=nrows, low_memory=False)
        else:
            df = pd.read_csv(path, low_memory=False)
        print(f"Shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        print(f"Label distribution (if 'label' column exists):")
        if "label" in df.columns:
            print(df["label"].value_counts(dropna=False).to_string())
        elif "Label" in df.columns:
            print(df["Label"].value_counts(dropna=False).to_string())
        print(f"\nNull counts:")
        print(df.isnull().sum().to_string())
        print(f"\nFirst row sample (truncated):")
        for col in df.columns:
            val = str(df.iloc[0][col])[:100]
            print(f"  {col}: {val}")
    except Exception as e:
        print(f"ERROR: {e}")

def main():
    files = sorted(os.listdir(DATASET_DIR))
    csv_files = [f for f in files if f.endswith(".csv")]
    for fname in csv_files:
        path = os.path.join(DATASET_DIR, fname)
        size_mb = os.path.getsize(path) / (1024*1024)
        # For very large files, only read first 5000 rows for exploration
        nrows = 5000 if size_mb > 50 else None
        explore_csv(fname, path, nrows)

if __name__ == "__main__":
    main()
