"""
Phase 2: Data preprocessing script.
- Loads all CSV datasets from datasets/
- Normalizes to common format: text (subject+body), label (0=safe, 1=spam/phishing)
- Cleans text (removes HTML, URLs, special chars)
- Merges all datasets into unified one
- Creates train/test split
- Saves preprocessed data to data/processed.csv and data/train_test_split/
Run: python scripts/preprocess_data.py
"""
import os
import re
import string
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")

warnings.filterwarnings("ignore")


def clean_text(text):
    """Clean email text: remove HTML, URLs, extra whitespace."""
    if not isinstance(text, str):
        return ""
    # Remove URLs
    text = re.sub(r"http\S+|https\S+|www\S+", "", text, flags=re.MULTILINE)
    # Remove HTML tags
    text = re.sub(r"<.*?>", " ", text, flags=re.DOTALL)
    # Remove extra whitespace/newlines
    text = re.sub(r"\s+", " ", text).strip()
    # Remove punctuation (but keep some context)
    text = text.translate(str.maketrans("", "", string.punctuation))
    # Lowercase
    text = text.lower()
    return text


def infer_label_from_schema(df):
    """Try to find the label column in various possible names."""
    for col in df.columns:
        if col.strip().lower() in ("label", "spam", "class", "target", "v1"):
            return col
    return None


def load_and_normalize_csv(filepath, filename):
    """Load a CSV and normalize its columns to: text, label."""
    try:
        df = pd.read_csv(filepath, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(filepath, low_memory=False, encoding="latin-1")

    # Find label column
    label_col = infer_label_from_schema(df)
    if label_col is None:
        print(f"  ⚠️  No label column found in {filename}, skipping label.")
        # If no label column, we can't train; skip
        return None, None

    # Normalize text column based on dataset format
    text_cols = [c for c in df.columns if c.strip().lower() in ("subject", "body", "text", "content", "v2")]
    if not text_cols:
        # Fallback: use first non-label column that looks like text
        text_cols = [c for c in df.columns if c.strip().lower() not in ("label",)]

    # Ensure label is numeric 0/1
    try:
        # Handle SMS label formats
        if label_col.strip().lower() == "v1" or label_col == "LABEL":
            # Normalize SMS labels
            def normalize_sms_label(label):
                if pd.isna(label):
                    return 0
                label_str = str(label).strip().lower()
                if label_str == "ham":
                    return 0
                elif label_str in ("spam", "smishing"):
                    return 1
                else:
                    return 0  # default to safe for unknown values

            df["label"] = df[label_col].apply(normalize_sms_label)
        else:
            df["label"] = pd.to_numeric(df[label_col], errors="coerce").fillna(0).astype(int)
    except Exception:
        df["label"] = 0

    # Build text column: combine subject and body if available
    subject_cols = [c for c in df.columns if c.strip().lower() == "subject"]
    body_cols = [c for c in df.columns if c.strip().lower() == "body"]
    if subject_cols and body_cols:
        df["text"] = df[subject_cols[0]].fillna("") + " " + df[body_cols[0]].fillna("")
    elif "v2" in df.columns:
        df["text"] = df["v2"]
    elif "TEXT" in df.columns:
        df["text"] = df["TEXT"]
    elif "text_combined" in df.columns:
        df["text"] = df["text_combined"]
    elif body_cols:
        df["text"] = df[body_cols[0]]
    elif subject_cols:
        df["text"] = df[subject_cols[0]]
    else:
        df["text"] = ""

    # Clean text
    df["text"] = df["text"].apply(clean_text)

    # Keep only needed columns
    df_out = df[["text", "label"]].copy()
    df_out = df_out.dropna(subset=["text"])
    df_out = df_out[df_out["text"].str.strip() != ""]

    print(f"  [OK] {filename}: {len(df_out)} rows (label={df_out['label'].value_counts().to_dict()})")
    return df_out, df[label_col].name if label_col else None


def main():
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    all_dfs = []
    label_sources = []

    csv_files = []
    for root, dirs, files in os.walk(DATASET_DIR):
        for fname in files:
            if fname.endswith(".csv"):
                csv_files.append(os.path.join(root, fname))
    csv_files = sorted(csv_files)

    for filepath in csv_files:
        fname = os.path.basename(filepath)
        print(f"\nProcessing {fname}...")
        df, label_src = load_and_normalize_csv(filepath, fname)
        if df is not None:
            all_dfs.append(df)
            if label_src:
                label_sources.append(label_src)

    if not all_dfs:
        print("❌ No data could be loaded. Exiting.")
        return

    # Merge all datasets
    merged = pd.concat(all_dfs, ignore_index=True)
    print(f"\n[TOTAL] Total merged rows: {len(merged)}")

    # Shuffle
    merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)

    # Label distribution
    print(f"[DIST] Label distribution after merge:\n{merged['label'].value_counts().to_string()}")

    # Save full processed dataset
    processed_path = os.path.join(PROCESSED_DIR, "processed.csv")
    merged.to_csv(processed_path, index=False)
    print(f"\n[SAVE] Saved processed data to: {processed_path}")

    # Train/test split
    train_df, test_df = train_test_split(
        merged, test_size=0.2, random_state=42, stratify=merged["label"]
    )

    train_path = os.path.join(PROCESSED_DIR, "train.csv")
    test_path = os.path.join(PROCESSED_DIR, "test.csv")

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"[SAVE] Saved train data to: {train_path} ({len(train_df)} rows)")
    print(f"[SAVE] Saved test data to:   {test_path} ({len(test_df)} rows)")

    # Save label mapping info
    label_counts = merged["label"].value_counts().to_dict()
    mapping = {0: "safe/ham", 1: "spam/phishing/smishing"}
    with open(os.path.join(os.path.dirname(__file__), "..", "data", "label_mapping.txt"), "w") as f:
        f.write("Label mapping:\n")
        f.write(f"  0 = {mapping[0]}\n")
        f.write(f"  1 = {mapping[1]}\n")
        f.write(f"\nClass distribution in full dataset: {label_counts}\n")

    print(f"\n[SAVE] Saved label mapping to: data/label_mapping.txt")
    print("\n[OK] Phase 2 complete: Data preprocessing finished!")


if __name__ == "__main__":
    main()