"""
Automated Integration Tests for InboxSentinel Web Server & APIs
"""
import sys
import json
import time
import threading
import urllib.request
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from src.scan_email import load_model
from src.web_server import InboxSentinelHandler, ThreadingHTTPServer

TEST_PORT = 8765
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


def start_test_server():
    model = load_model()
    server = ThreadingHTTPServer(("127.0.0.1", TEST_PORT), InboxSentinelHandler)
    server.model = model
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    return server


def test_endpoints():
    server = start_test_server()
    print("Test server started.")

    try:
        # 1. Health check
        with urllib.request.urlopen(f"{BASE_URL}/api/health") as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert data["status"] == "healthy"
            print("✅ /api/health passed")

        # 2. Presets check
        with urllib.request.urlopen(f"{BASE_URL}/api/presets") as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert len(data) >= 5
            print(f"✅ /api/presets passed ({len(data)} presets loaded)")

        # 3. Single Scan Phishing
        req_body = json.dumps({
            "text": "URGENT: Your Wells Fargo bank account has been suspended. Click here to verify your identity: http://fake-login-bank.com",
            "mode": "email"
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/api/scan", data=req_body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert data["is_threat"] is True
            assert "indicators" in data
            assert len(data["indicators"]["urgency_triggers"]) > 0
            assert len(data["indicators"]["credential_triggers"]) > 0
            print("✅ /api/scan (Phishing threat) passed:", data["label_name"], f"({data['confidence']}%)")

        # 4. Single Scan Safe
        req_body = json.dumps({
            "text": "Hi team, please find attached the weekly summary report. Let me know if you have questions.",
            "mode": "email"
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/api/scan", data=req_body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert data["is_threat"] is False
            print("✅ /api/scan (Safe ham) passed:", data["label_name"], f"({data['confidence']}%)")

        # 5. Batch Scan
        req_body = json.dumps({
            "items": [
                "Hi John, review proposal please",
                "CONGRATULATIONS! You won $1,000,000 in international lottery! Click here now!",
                "Team standup is postponed to 4pm"
            ],
            "mode": "email"
        }).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}/api/batch", data=req_body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as res:
            assert res.status == 200
            data = json.loads(res.read().decode())
            assert data["summary"]["total"] == 3
            assert data["summary"]["safe_count"] == 2
            assert data["summary"]["threat_count"] == 1
            print("✅ /api/batch passed: Total 3, Safe 2, Threat 1")

        # 6. Static files check
        with urllib.request.urlopen(f"{BASE_URL}/index.html") as res:
            assert res.status == 200
            content = res.read().decode()
            assert "InboxSentinel" in content
            print("✅ Static /index.html passed")

        with urllib.request.urlopen(f"{BASE_URL}/style.css") as res:
            assert res.status == 200
            print("✅ Static /style.css passed")

        with urllib.request.urlopen(f"{BASE_URL}/app.js") as res:
            assert res.status == 200
            print("✅ Static /app.js passed")

        print("\n🎉 ALL UI & API TESTS PASSED SUCCESSFULLY!")

    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    test_endpoints()
