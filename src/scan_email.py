"""
Phase 4: Email Scanner CLI

Scan individual emails or batches of emails and classify them as:
  - SAFE [HAM]
  - SPAM / PHISHING [THREAT]

Usage:
  python src/scan_email.py --text "Free money now!!!"
  python src/scan_email.py --email "Free money now!!!"
  python src/scan_email.py --file email.txt
  python src/scan_email.py --batch emails.txt
"""
import os
import re
import sys
import json
import joblib
import argparse
import string
from pathlib import Path

# Model location
BASE_DIR = Path(__file__).parent.parent
MODELS_DIR = BASE_DIR / "models"

SPAM_MODEL_PATH = MODELS_DIR / "spam_detector.pkl"
VECTORIZER_PATH = MODELS_DIR / "tfidf_vectorizer.pkl"

# Label mapping
LABELS = {
    0: "SAFE [HAM]",
    1: "SPAM / PHISHING [THREAT]",
}


def clean_text(text):
    """Clean email text to match training pipeline format."""
    if not isinstance(text, str):
        return ""
    # Remove URLs
    text = re.sub(r"http\S+|https\S+|www\S+", "", text, flags=re.MULTILINE)
    # Remove HTML tags
    text = re.sub(r"<.*?>", " ", text, flags=re.DOTALL)
    # Remove extra whitespace
    text = re.sub(r"\s+", " ", text).strip()
    # Remove punctuation
    text = text.translate(str.maketrans("", "", string.punctuation))
    # Lowercase
    text = text.lower()
    return text


def load_model():
    """Load the trained spam detection model."""
    if not SPAM_MODEL_PATH.exists():
        print(f"ERROR: Model not found at {SPAM_MODEL_PATH}")
        print("Run 'python scripts/train_model.py' first to train the model.")
        sys.exit(1)

    model = joblib.load(SPAM_MODEL_PATH)
    return model


def scan_email(model, email_text):
    """
    Scan a single email and return classification result.

    Returns:
        dict with keys: text, label, label_name, confidence, is_spam
    """
    # Clean the email text
    cleaned_text = clean_text(email_text)

    # Predict
    prediction = model.predict([cleaned_text])[0]
    probabilities = model.predict_proba([cleaned_text])[0]
    confidence = float(max(probabilities) * 100)

    # Get probability of spam if relevant
    spam_prob = float(probabilities[1]) * 100 if len(probabilities) > 1 else 0.0

    result = {
        "text_preview": email_text[:200] + ("..." if len(email_text) > 200 else ""),
        "label": int(prediction),
        "label_name": LABELS.get(prediction, "UNKNOWN"),
        "confidence": round(confidence, 2),
        "spam_probability": round(spam_prob, 2),
        "is_spam_or_phishing": prediction == 1,
    }
    return result


def scan_email_file(model, filepath):
    """Scan a single email from a file."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return scan_email(model, text)


def scan_email_batch(model, filepath):
    """Scan multiple emails from a text file (one per line)."""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if line:
            result = scan_email(model, line)
            result["email_number"] = i
            results.append(result)

    return results


def format_result(result):
    """Format a result dict for pretty printing."""
    print(f"\n--- Email Analysis Result ---")
    print(f"  Preview:    {result['text_preview']}")
    print(f"  Status:     {result['label_name']}")
    print(f"  Label:      {result['label']} (0=safe, 1=spam/phishing)")
    print(f"  Confidence: {result['confidence']}%")
    print(f"  Spam Prob:  {result['spam_probability']}%")
    print(f"  Threat:     {'YES - This email is SPAM/PHISHING!' if result['is_spam_or_phishing'] else 'NO - This email appears safe.'}")


def format_batch_results(results):
    """Format batch results for display."""
    safe_count = 0
    spam_count = 0

    print(f"\n{'='*70}")
    print("BATCH SCAN SUMMARY")
    print(f"{'='*70}")

    for r in results:
        status = "SPAM" if r["is_spam_or_phishing"] else "SAFE"
        if r["is_spam_or_phishing"]:
            spam_count += 1
        else:
            safe_count += 1
        print(f"\n  Email #{r.get('email_number', '?')}: [{status}] ({r['confidence']}% confidence)")
        print(f"    Preview: {r['text_preview']}")

    print(f"\n{'='*70}")
    print(f"Total emails scanned:  {len(results)}")
    print(f"  Safe emails:    {safe_count}")
    print(f"  Spam/Phishing:  {spam_count}")
    print(f"{'='*70}")

    return {"total": len(results), "safe": safe_count, "spam": spam_count}


def main():
    parser = argparse.ArgumentParser(
        description="InboxSentinel - AI-Powered Email Spam Detection"
    )
    parser.add_argument(
        "--text", "--email", type=str, default=None,
        dest="text",
        help="Email text to scan directly"
    )
    parser.add_argument(
        "--file", type=str, default=None,
        help="Path to a file containing a single email"
    )
    parser.add_argument(
        "--batch", type=str, default=None,
        help="Path to a file with one email per line for batch scanning"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results in JSON format"
    )

    args = parser.parse_args()

    # Load model
    model = load_model()

    # Single email from text
    if args.text:
        result = scan_email(model, args.text)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            format_result(result)

    # Single email from file
    elif args.file:
        if not os.path.exists(args.file):
            print(f"ERROR: File not found: {args.file}")
            sys.exit(1)
        result = scan_email_file(model, args.file)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            format_result(result)

    # Batch scanning
    elif args.batch:
        if not os.path.exists(args.batch):
            print(f"ERROR: File not found: {args.batch}")
            sys.exit(1)
        results = scan_email_batch(model, args.batch)
        if args.json:
            print(json.dumps({
                "summary": format_batch_results([]) if args.json else None,
                "results": results
            }, indent=2))
        else:
            format_batch_results(results)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()