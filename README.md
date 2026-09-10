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
pip install -r requirements.txt
python src/scan_email.py --email "your_email_text_here"
```

## Phases
1. **Phase 1**: Project setup ✅ Done
2. **Phase 2**: Data exploration and preprocessing
3. **Phase 3**: AI model training
4. **Phase 4**: Email scanner interface
5. **Phase 5**: Testing and validation

## Datasets Used
- CEAS_08.csv, SpamAssasin.csv, Nigerian_Fraud.csv, phishing_email.csv, Ling.csv, Nazario.csv, Enron.csv