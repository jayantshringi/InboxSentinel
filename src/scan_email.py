"""
Phase 4: Email & SMS Scanner CLI

Scan individual emails or SMS messages and classify them as:
  - SAFE [HAM]
  - SPAM / PHISHING / SMISHING [THREAT]

Usage:
  python src/scan_email.py --text "Free money now!!!"
  python src/scan_email.py --email "Free money now!!!"
  python src/scan_email.py --file email.txt
  python src/scan_email.py --batch emails.txt
  python src/scan_email.py --sms "Free prize! Click here now!"
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
    1: "SPAM / PHISHING / SMISHING [THREAT]",
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


def clean_sms_text(text):
    """Clean SMS text to match training pipeline format.

    SMS messages are shorter and rarely contain HTML, but may include
    URLs, phone numbers, and special characters. We normalize whitespace
    and lowercase but preserve URLs/phone numbers for context.
    """
    if not isinstance(text, str):
        return ""
    # Normalize whitespace/newlines
    text = re.sub(r"\s+", " ", text).strip()
    # Remove HTML tags (rare in SMS but possible)
    text = re.sub(r"<.*?>", " ", text, flags=re.DOTALL)
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

    # Check if input is only an email address or lacks sufficient text
    warning = None
    if re.fullmatch(r"^[\w\.-]+@[\w\.-]+\.\w+$", email_text.strip()):
        warning = "You provided an email address instead of the email message body. InboxSentinel is designed to scan email content/text."
    elif not cleaned_text.strip():
        warning = "Input text contains no recognizable words after preprocessing."

    result = {
        "text_preview": email_text[:200] + ("..." if len(email_text) > 200 else ""),
        "label": int(prediction),
        "label_name": LABELS.get(prediction, "UNKNOWN"),
        "confidence": round(confidence, 2),
        "spam_probability": round(spam_prob, 2),
        "is_spam_or_phishing": prediction == 1,
    }
    if warning:
        result["warning"] = warning
    return result


def scan_email_file(model, filepath):
    """Scan a single email from a file."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return scan_email(model, text)


def scan_email_batch(model, filepath, source="email"):
    """Scan multiple emails/SMS from a text file (one per line)."""
    results = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if line:
            if source == "sms":
                result = scan_sms(model, line)
            else:
                result = scan_email(model, line)
            result["email_number"] = i
            results.append(result)

    return results


def scan_sms(model, sms_text):
    """
    Scan a single SMS message and return classification result.

    Returns:
        dict with keys: text, label, label_name, confidence, is_spam
    """
    # Clean the SMS text
    cleaned_text = clean_sms_text(sms_text)

    # Predict
    prediction = model.predict([cleaned_text])[0]
    probabilities = model.predict_proba([cleaned_text])[0]
    confidence = float(max(probabilities) * 100)

    # Get probability of spam if relevant
    spam_prob = float(probabilities[1]) * 100 if len(probabilities) > 1 else 0.0

    # Check if input is only a phone number or lacks sufficient text
    warning = None
    if re.fullmatch(r"^[\d\s\-\+\(\)]{7,}$", sms_text.strip()):
        warning = "You provided a phone number instead of the SMS message body. InboxSentinel is designed to scan SMS content/text."
    elif not cleaned_text.strip():
        warning = "Input text contains no recognizable words after preprocessing."

    result = {
        "text_preview": sms_text[:200] + ("..." if len(sms_text) > 200 else ""),
        "label": int(prediction),
        "label_name": LABELS.get(prediction, "UNKNOWN"),
        "confidence": round(confidence, 2),
        "spam_probability": round(spam_prob, 2),
        "is_spam_or_phishing": prediction == 1,
        "source": "sms",
    }
    if warning:
        result["warning"] = warning
    return result


def format_result(result):
    """Format a result dict for pretty printing."""
    source = result.get("source", "email").upper()
    print(f"\n--- {source} Analysis Result ---")
    print(f"  Preview:    {result['text_preview']}")
    print(f"  Status:     {result['label_name']}")
    print(f"  Label:      {result['label']} (0=safe, 1=spam/phishing/smishing)")
    print(f"  Confidence: {result['confidence']}%")
    print(f"  Spam Prob:  {result['spam_probability']}%")
    print(f"  Threat:     {'YES - This message is SPAM/PHISHING/SMISHING!' if result['is_spam_or_phishing'] else 'NO - This message appears safe.'}")
    if result.get("warning"):
        print(f"\n  [TIP] {result['warning']}")


def format_batch_results(results):
    """Format batch results for display."""
    safe_count = 0
    spam_count = 0

    if not results:
        source = "email"
    else:
        source = "email"
        for r in results:
            if r.get("source") in ["email", "sms"]:
                source = r.get("source")
                break

    source_label = source.upper()

    print(f"\n{'='*70}")
    print(f"{source_label.upper()} BATCH SCAN SUMMARY")
    print(f"{'='*70}")

    for r in results:
        status = "SPAM" if r["is_spam_or_phishing"] else "SAFE"
        if r["is_spam_or_phishing"]:
            spam_count += 1
        else:
            safe_count += 1
        preview = r['text_preview']
        # Truncate preview to show more context for SMS
        if source == "sms" and len(preview) > 100:
            preview = preview[:100] + "..."
        print(f"\n  {source_label.upper()} #{r.get('email_number', '?')}: [{status}] ({r['confidence']}% confidence)")
        print(f"    Preview: {preview}")

    print(f"\n{'='*70}")
    total = len(results)
    print(f"  Total {source_label} scanned:  {total}")
    print(f"  Safe:    {safe_count}")
    print(f"  Spam/Phishing/Smishing:  {spam_count}")
    print(f"{'='*70}")

    return {"total": total, "safe": safe_count, "spam": spam_count}


def main():
    parser = argparse.ArgumentParser(
        description="InboxSentinel - AI-Powered Email & SMS Spam Detection"
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
        "--sms-batch", type=str, default=None, dest="sms_batch",
        help="Path to a file with one SMS message per line for batch SMS scanning"
    )
    parser.add_argument(
        "--sms", type=str, default=None,
        help="Scan an SMS message directly"
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
        results = scan_email_batch(model, args.batch, source="email")
        if args.json:
            print(json.dumps({
                "summary": format_batch_results([]) if args.json else None,
                "results": results
            }, indent=2))
        else:
            format_batch_results(results)

    # Batch SMS scanning
    elif args.sms_batch:
        if not os.path.exists(args.sms_batch):
            print(f"ERROR: File not found: {args.sms_batch}")
            sys.exit(1)
        results = scan_email_batch(model, args.sms_batch, source="sms")
        if args.json:
            print(json.dumps({
                "summary": format_batch_results([]) if args.json else None,
                "results": results
            }, indent=2))
        else:
            format_batch_results(results)

    # Single SMS scan
    elif args.sms:
        result = scan_sms(model, args.sms)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            format_result(result)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()