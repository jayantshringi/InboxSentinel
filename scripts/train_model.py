"""
Phase 3: AI Model Training for Email Spam Detection
- Uses TF-IDF vectorization + Logistic Regression classifier
- Trains on the preprocessed data from Phase 2
- Evaluates model performance
- Saves the trained model and vectorizer
Run: python scripts/train_model.py
"""
import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

os.makedirs(MODELS_DIR, exist_ok=True)


def train_model():
    """Train the spam detection model."""
    print("[LOAD] Loading training data...")
    train_path = os.path.join(DATA_DIR, "train.csv")
    test_path = os.path.join(DATA_DIR, "test.csv")

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    print(f"  Train samples: {len(train_df)}")
    print(f"  Test samples:  {len(test_df)}")
    print(f"  Train labels: {train_df['label'].value_counts().to_dict()}")
    print(f"  Test labels:  {test_df['label'].value_counts().to_dict()}")

    # Build pipeline: TF-IDF + Logistic Regression
    print("\n[BUILD] Building model pipeline (TF-IDF + Logistic Regression)...")
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words="english",
            lowercase=True,
            strip_accents="ascii",
        )),
        ("clf", LogisticRegression(
            random_state=42,
            max_iter=1000,
            class_weight="balanced",
        )),
    ])

    # Train
    print("\n[TRAIN] Fitting model on training data...")
    X_train = train_df["text"]
    y_train = train_df["label"]
    model.fit(X_train, y_train)

    # Evaluate
    print("\n[EVAL] Evaluating on test data...")
    X_test = test_df["text"]
    y_test = test_df["label"]

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["safe (0)", "spam/phishing (1)"], output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n[OK] Accuracy: {acc*100:.2f}%")
    print("\n[REPORT] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["safe (0)", "spam/phishing (1)"]))

    print("\n[MATRIX] Confusion Matrix:")
    print(cm)

    # Save model and vectorizer
    model_path = os.path.join(MODELS_DIR, "spam_detector.pkl")
    vectorizer_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")

    joblib.dump(model, model_path)
    joblib.dump(model.named_steps["tfidf"], vectorizer_path)

    print(f"\n[SAVE] Saved model to: {model_path}")
    print(f"[SAVE] Saved vectorizer to: {vectorizer_path}")

    # Also save class names for inference
    metadata = {
        "classes": ["safe (label=0)", "spam/phishing (label=1)"],
        "accuracy": float(acc),
        "max_features": 5000,
        "ngram_range": [1, 2],
    }
    metadata_path = os.path.join(MODELS_DIR, "model_metadata.json")
    import json
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[SAVE] Saved metadata to: {metadata_path}")

    return model


def predict_email(model, email_text):
    """Predict whether a single email is safe or spam/phishing."""
    prediction = model.predict([email_text])[0]
    probability = model.predict_proba([email_text])[0]
    confidence = max(probability) * 100

    label_map = {0: "SAFE [HAM]", 1: "SPAM/PHISHING [THREAT]"}
    result = label_map.get(prediction, "UNKNOWN")

    return result, confidence


def main():
    print("=" * 60)
    print("InboxSentinel - Email Spam Detection Training")
    print("=" * 60)

    model = train_model()

    # Interactive test
    print("\n" + "=" * 60)
    print("Test your own email (type 'quit' to exit):")
    print("=" * 60)

    while True:
        user_input = input("\nEnter email text: ").strip()
        if user_input.lower() in ("quit", "exit", "q"):
            break

        if not user_input:
            continue

        result, confidence = predict_email(model, user_input)
        print(f"\nResult: {result}")
        print(f"Confidence: {confidence:.2f}%")


if __name__ == "__main__":
    main()