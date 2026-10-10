"""
Phase 5: Validation - Run model on test set and report final metrics.
Run: python scripts/validate_model.py
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def main():
    print("="*60)
    print("InboxSentinel - Model Validation on Test Set")
    print("="*60)

    # Load model
    model_path = os.path.join(MODELS_DIR, "spam_detector.pkl")
    print(f"\n[LOAD] Loading model from {model_path}...")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}")
    model = joblib.load(model_path)
    print("  Model loaded successfully.")

    # Check and load test data
    test_path = os.path.join(DATA_DIR, "test.csv")
    has_test_dataset = False
    test_df = None

    if os.path.exists(test_path):
        try:
            with open(test_path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()
                if "version https://git-lfs" not in first_line and "oid sha256" not in first_line:
                    test_df = pd.read_csv(test_path)
                    if "text" in test_df.columns and "label" in test_df.columns:
                        has_test_dataset = True
                else:
                    print(f"\n[INFO] {test_path} is a Git LFS pointer (not fully checked out in CI).")
        except Exception as e:
            print(f"  [WARN] Could not parse {test_path}: {e}")

    if has_test_dataset and test_df is not None:
        print(f"\n[LOAD] Loading test data from {test_path}...")
        print(f"  Total test samples: {len(test_df)}")

        # Predict
        X_test = test_df["text"]
        y_test = test_df["label"]

        print("\n[PREDICT] Running predictions on test set...")
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        # Metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        try:
            auc = roc_auc_score(y_test, y_proba)
        except Exception:
            auc = None

        cm = confusion_matrix(y_test, y_pred)

        print(f"\n[METRICS] Final test-set performance:")
        print(f"   Accuracy:  {acc*100:.2f}%")
        print(f"   Precision: {prec*100:.2f}%")
        print(f"   Recall:    {rec*100:.2f}%")
        print(f"   F1 Score:  {f1*100:.2f}%")
        if auc is not None:
            print(f"   ROC-AUC:   {auc*100:.2f}%")

        print(f"\n[MATRIX] Confusion Matrix:")
        print(f"   {cm}")
        print(f"   True Negatives (correct safe):    {cm[0][0]}")
        print(f"   False Positives (safe as spam):   {cm[0][1]}")
        print(f"   False Negatives (spam as safe):   {cm[1][0]}")
        print(f"   True Positives (correct spam):    {cm[1][1]}")

        print(f"\n[REPORT] Detailed Classification Report:")
        print(classification_report(y_test, y_pred, target_names=["safe (0)", "spam/phishing (1)"]))

        # Validation summary
        print(f"\n[INFO] Threat detection summary:")
        total = len(y_test)
        actual_spam = int(y_test.sum())
        detected_spam = int((y_pred == 1).sum())
        correct = int((y_pred == y_test).sum())
        print(f"   Actual spam emails:    {actual_spam} / {total} ({actual_spam/total*100:.1f}%)")
        print(f"   Detected as spam:      {detected_spam} / {total} ({detected_spam/total*100:.1f}%)")
        print(f"   Correctly classified:  {correct} / {total} ({correct/total*100:.1f}%)")
    else:
        print("\n[SKIP] Full test dataset CSV not available locally; proceeding with sample verification.")

    # Test with sample known spam/phishing patterns
    print(f"\n[INFO] Sample-based validation:")
    samples = [
        ("Get rich quick! Invest $100 and earn $10000 in 24 hours!", 1, "Crypto spam"),
        ("Hi, can we reschedule our meeting to next Tuesday?", 0, "Normal email"),
        ("URGENT: Your account has been compromised! Click here to verify.", 1, "Phishing"),
        ("Thanks for the birthday wishes!", 0, "Friendly email"),
        ("Winner! Claim your $5,000,000 prize now! Click the link below.", 1, "Lottery scam"),
    ]

    failed_samples = 0
    for text, expected, desc in samples:
        result = model.predict([text.lower().replace(".", "").replace("!", "").replace(",", "").replace("?", "")])[0]
        match = "PASS" if result == expected else "FAIL"
        if match == "FAIL":
            failed_samples += 1
        print(f"   [{match}] '{desc}' - expected: {expected}, got: {result}")

    if failed_samples > 0:
        raise AssertionError(f"{failed_samples} sample validation checks failed!")

    print(f"\n[OK] Validation complete!")


if __name__ == "__main__":
    main()