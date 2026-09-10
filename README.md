# InboxSentinel - AI-Powered Email Spam Detection

An intelligent email scanning system that classifies emails as **Safe**, **Spam**, or **Phishing** using machine learning.

## Features
- Scan individual emails or batch process multiple emails
- AI-powered classification (Safe / Spam / Phishing)
- Confidence score for each prediction
- Training on multiple public email datasets

## Project Structure
```
InboxSentinel/
├── src/           # Main source code
├── data/          # Processed datasets
├── models/        # Trained models
├── scripts/       # Utility scripts
├── tests/         # Test files
├── datasets/      # Raw datasets (CSV files)
├── requirements.txt
├── README.md
└── memory.md      # Project task tracking
```

## Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# Scan a single email (pass the message body / subject text)
python src/scan_email.py --email "Hi John, please find attached the Q3 financial report. Let me know if you have questions."

# Scan a suspicious / phishing email
python src/scan_email.py --email "URGENT: Your account has been suspended. Click here to verify your identity: http://fake-login-bank.com"

# Batch scan a file of emails
python src/scan_email.py --batch tests/test_emails.txt
```

## Phases
1. **Phase 1**: Project setup ✅ Done
2. **Phase 2**: Data exploration and preprocessing
3. **Phase 3**: AI model training
4. **Phase 4**: Email scanner interface
5. **Phase 5**: Testing and validation

## Datasets Used
- CEAS_08.csv, SpamAssasin.csv, Nigerian_Fraud.csv, phishing_email.csv, Ling.csv, Nazario.csv, Enron.csv