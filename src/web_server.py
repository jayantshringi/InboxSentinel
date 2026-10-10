"""
InboxSentinel Web Application Server

Lightweight, high-performance HTTP server providing a REST API and serving the
Cyber-Sentinel Web Interface for real-time email, SMS, and EML threat analysis.
Zero external framework dependencies (uses Python standard library ThreadingHTTPServer).
"""
import os
import sys
import json
import argparse
from pathlib import Path
from http import HTTPStatus
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

# Import ML model and scanning logic from scan_email and threat_analyzer
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.scan_email import load_model, scan_email, scan_sms
from src.threat_analyzer import analyze_threat_indicators, parse_eml_content

UI_DIR = Path(__file__).parent / "ui"
MAX_PAYLOAD_SIZE = 5 * 1024 * 1024  # 5 MB max payload guard

# Curated presets for instant testing
SAMPLE_PRESETS = [
    {
        "id": "bank_phishing",
        "title": "Bank Account Phishing",
        "category": "Phishing",
        "type": "email",
        "description": "Urgent security alert demanding immediate credentials verification.",
        "text": "URGENT: Your Wells Fargo bank account has been suspended due to unauthorized access attempts. Click here to verify your identity within 24 hours to prevent permanent deactivation: http://fake-login-bank.com/auth"
    },
    {
        "id": "eml_spoof",
        "title": "EML: Brand Header Spoofing",
        "category": "Email Forensics (.EML)",
        "type": "eml",
        "description": "RFC 822 email headers spoofing PayPal with an unauthorized external domain and failed SPF.",
        "text": "From: \"PayPal Billing Dept\" <billing-notice@mail-account-update19.xyz>\nReply-To: security-drop@hacker-collector.top\nTo: customer@example.com\nSubject: Critical Security Notice: Unauthorized Transaction\nDate: Sat, 10 Oct 2026 09:12:00 +0000\nAuthentication-Results: mx.example.com; spf=fail smtp.mailfrom=mail-account-update19.xyz; dkim=fail\n\nDear Valued Customer,\n\nWe detected unauthorized login attempts from a new location. Your account has been temporarily restricted.\n\nClick here to verify your identity within 24 hours: http://paypa1-security.xyz/auth\n\nThank you,\nPayPal Support Team"
    },
    {
        "id": "crypto_scam",
        "title": "Crypto 1000% Returns",
        "category": "Financial Scam",
        "type": "email",
        "description": "Unrealistic high-yield crypto investment lure.",
        "text": "Get rich quick! Invest in our revolutionary crypto scheme and earn 1000% returns in one week! Send Bitcoin to our guaranteed escrow wallet now before the private round closes."
    },
    {
        "id": "nigerian_prince",
        "title": "Nigerian Inheritance Proposal",
        "category": "Advance Fee Fraud",
        "type": "email",
        "description": "Classic 419 inheritance transfer wire proposal.",
        "text": "Dear Valued Friend, I am Prince Abubakar. I need your urgent assistance to transfer $50 million dollars out of Nigeria. You will receive 30% commission as beneficiary. Kindly reply with your full bank details and passport copy."
    },
    {
        "id": "safe_work",
        "title": "Legitimate Team Sync",
        "category": "Safe / Ham",
        "type": "email",
        "description": "Normal enterprise workplace email.",
        "text": "Hi Team, please find attached the Q3 financial report. Let me know if you have any questions before the review meeting at 3pm today. Please update your calendars."
    },
    {
        "id": "safe_dental",
        "title": "Doctor Appointment Reminder",
        "category": "Safe / Ham",
        "type": "email",
        "description": "Standard service appointment reminder.",
        "text": "Reminder: Your dental checkup is scheduled for next Tuesday at 2:00 PM with Dr. Roberts. If you need to reschedule, please call our front desk at least 24 hours prior. Have a great day!"
    },
    {
        "id": "sms_parcel",
        "title": "FedEx / Postal Smishing",
        "category": "Smishing (SMS)",
        "type": "sms",
        "description": "Fake delivery fee SMS lure with malicious link.",
        "text": "USPS: Your parcel delivery is held at our depot due to an unpaid $1.99 customs fee. Action required today: http://parcel-tracking-update.xyz/pay or package will be returned to sender."
    },
    {
        "id": "sms_lottery",
        "title": "Lottery Prize Win SMS",
        "category": "Smishing (SMS)",
        "type": "sms",
        "description": "Unsolicited prize winner scam SMS.",
        "text": "Congratulations! You won a $1,000 Walmart Gift Card in our mystery draw. Free msg: claim your reward now at http://win-claim-voucher.top/win. Reply STOP to opt out."
    }
]


class InboxSentinelHandler(SimpleHTTPRequestHandler):
    """Custom request handler with REST API routing and static file serving."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def end_headers(self):
        # Enable CORS and disable aggressive caching for development
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self):
        # API Routes
        if self.path == "/api/health":
            self.send_json_response({
                "status": "healthy",
                "version": "1.1.0",
                "model_name": "TF-IDF + Logistic Regression (Enhanced Forensics)",
                "accuracy": 98.3,
                "classes": ["Safe (0)", "Threat (1)"],
                "features": ["email", "sms", "eml_forensics", "homoglyphs", "typosquatting", "token_highlighting"]
            })
            return

        elif self.path == "/api/presets":
            self.send_json_response(SAMPLE_PRESETS)
            return

        elif self.path == "/api/stats":
            meta_path = BASE_DIR / "models" / "model_metadata.json"
            meta = {}
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    pass
            self.send_json_response(meta)
            return

        # Route static UI files
        if self.path in ["", "/"]:
            self.path = "/index.html"
        elif self.path == "/favicon.ico":
            self.path = "/favicon.svg"

        super().do_GET()

    def do_POST(self):
        # Enforce payload size limit
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error_response("Invalid Content-Length header", HTTPStatus.BAD_REQUEST)
            return

        if content_length > MAX_PAYLOAD_SIZE:
            self.send_error_response(
                f"Payload too large. Maximum supported size is {MAX_PAYLOAD_SIZE // (1024 * 1024)}MB.",
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            )
            return

        # Parse body JSON
        try:
            post_body = self.rfile.read(content_length)
            data = json.loads(post_body.decode("utf-8")) if post_body else {}
        except Exception as e:
            self.send_error_response(f"Invalid JSON body: {str(e)}", HTTPStatus.BAD_REQUEST)
            return

        if self.path in ["/api/scan", "/api/scan-eml"]:
            if self.path == "/api/scan-eml":
                data["mode"] = "eml"
            self.handle_single_scan(data)
        elif self.path == "/api/batch":
            self.handle_batch_scan(data)
        else:
            self.send_error_response("Endpoint not found", HTTPStatus.NOT_FOUND)

    def handle_single_scan(self, data):
        text = data.get("text", "")
        mode = data.get("mode", "email").lower()
        is_eml = mode == "eml" or data.get("is_eml", False)

        if not text or not str(text).strip():
            self.send_error_response("Input text cannot be empty", HTTPStatus.BAD_REQUEST)
            return

        header_info = None
        text_to_scan = text

        # Automatic EML detection: mode == 'eml' or starting with standard RFC 822 headers
        if is_eml or (isinstance(text, str) and ("\nFrom: " in "\n" + text[:400] and ("\nSubject: " in "\n" + text[:400] or "\nTo: " in "\n" + text[:400]))):
            try:
                header_info = parse_eml_content(text)
                if header_info.get("extracted_body") or header_info.get("subject"):
                    text_to_scan = header_info.get("full_text") or header_info.get("extracted_body")
                    is_eml = True
            except Exception:
                header_info = None

        is_sms = mode == "sms"
        model = self.server.model

        # Perform ML scan
        if is_sms:
            ml_result = scan_sms(model, text_to_scan)
        else:
            ml_result = scan_email(model, text_to_scan)

        # Perform Heuristic & Forensic Threat Analysis
        indicators = analyze_threat_indicators(text_to_scan, is_sms=is_sms, header_info=header_info)

        # Calculate safe probability
        spam_prob = float(ml_result.get("spam_probability", 0.0))
        safe_prob = round(100.0 - spam_prob, 2)
        is_threat = bool(ml_result.get("is_spam_or_phishing", False))

        # Header alerts can escalate to threat
        header_alerts = indicators.get("header_alerts", [])
        if header_alerts and any(a.get("severity") == "CRITICAL" for a in header_alerts):
            is_threat = True
            if spam_prob < 50.0:
                spam_prob = 85.0
                safe_prob = 15.0

        label_val = 1 if is_threat else int(ml_result.get("label", 0))
        confidence_val = float(ml_result.get("confidence", 0.0))

        response_payload = {
            "mode": "eml" if is_eml else mode,
            "is_eml": is_eml,
            "label": label_val,
            "label_name": "SPAM / PHISHING / SMISHING [THREAT]" if is_threat else str(ml_result.get("label_name", "SAFE [HAM]")),
            "is_threat": is_threat,
            "confidence": confidence_val,
            "spam_probability": spam_prob,
            "safe_probability": safe_prob,
            "warning": ml_result.get("warning"),
            "text_preview": str(ml_result.get("text_preview", "")),
            "indicators": indicators,
            "header_info": header_info,
            "header_alerts": header_alerts,
            "highlight_spans": indicators.get("highlight_spans", []),
        }

        self.send_json_response(response_payload)

    def handle_batch_scan(self, data):
        raw_items = data.get("items", [])
        mode = data.get("mode", "email").lower()
        is_sms = mode == "sms"
        model = self.server.model

        if isinstance(raw_items, str):
            lines = [line.strip() for line in raw_items.splitlines() if line.strip()]
        elif isinstance(raw_items, list):
            lines = [str(item).strip() for item in raw_items if str(item).strip()]
        else:
            lines = []

        if not lines:
            self.send_error_response("No valid items to scan in batch", HTTPStatus.BAD_REQUEST)
            return

        results = []
        safe_count = 0
        threat_count = 0

        for idx, line in enumerate(lines, 1):
            if is_sms:
                ml_res = scan_sms(model, line)
            else:
                ml_res = scan_email(model, line)

            indicators = analyze_threat_indicators(line, is_sms=is_sms)
            is_threat = bool(ml_res.get("is_spam_or_phishing", False))

            if is_threat:
                threat_count += 1
            else:
                safe_count += 1

            results.append({
                "index": int(idx),
                "text": str(line),
                "preview": str(line[:120] + ("..." if len(line) > 120 else "")),
                "is_threat": is_threat,
                "label": int(ml_res.get("label", 0)),
                "confidence": float(ml_res.get("confidence", 0.0)),
                "spam_probability": float(ml_res.get("spam_probability", 0.0)),
                "risk_level": str(indicators.get("risk_level", "CLEAN")),
                "indicator_count": int(
                    len(indicators.get("urgency_triggers", [])) +
                    len(indicators.get("financial_triggers", [])) +
                    len(indicators.get("credential_triggers", [])) +
                    len(indicators.get("smishing_triggers", [])) +
                    len(indicators.get("urls", []))
                )
            })

        total = len(results)
        summary = {
            "total": int(total),
            "safe_count": int(safe_count),
            "threat_count": int(threat_count),
            "threat_percentage": round((threat_count / total * 100), 1) if total > 0 else 0,
            "mode": mode
        }

        self.send_json_response({
            "summary": summary,
            "results": results
        })

    def send_json_response(self, data, status=HTTPStatus.OK):
        def json_default(obj):
            if hasattr(obj, "item"):
                return obj.item()
            if hasattr(obj, "__bool__"):
                return bool(obj)
            return str(obj)

        payload = json.dumps(data, indent=2, default=json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_error_response(self, message, status=HTTPStatus.BAD_REQUEST):
        self.send_json_response({"error": message}, status=status)


def run_server(host="127.0.0.1", port=8000):
    """Starts the InboxSentinel Web Server."""
    print("=" * 65)
    print(" INBOXSENTINEL AI EMAIL & SMS THREAT DETECTION SYSTEM")
    print("=" * 65)
    print("Loading AI spam & threat detection model...")
    model = load_model()
    print("AI Model loaded successfully into memory.")

    # Try requested port or increment if busy
    selected_port = port
    server = None
    for attempt in range(5):
        try:
            server = ThreadingHTTPServer((host, selected_port), InboxSentinelHandler)
            server.model = model
            break
        except OSError as e:
            if attempt < 4:
                print(f"Port {selected_port} in use, trying port {selected_port + 1}...")
                selected_port += 1
            else:
                raise e

    url = f"http://{host}:{selected_port}"
    print(f"\n>> UI Server active and listening at: {url}")
    print(f">> REST API ready at: {url}/api/scan and {url}/api/batch")
    print(">> Press Ctrl+C in this terminal to stop the server.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down InboxSentinel UI Server...")
        server.server_close()
        print("Server stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InboxSentinel Minimal UI Web Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)
