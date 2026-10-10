"""
Unit & Integration Tests for InboxSentinel Threat Forensics Engine
Tests: EML parsing, header spoofing, typosquatting, homoglyphs, and token spans
"""
import sys
import json
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threat_analyzer import (
    parse_eml_content,
    analyze_email_headers,
    detect_homoglyphs,
    check_typosquatting,
    extract_urls,
    extract_threat_spans,
    analyze_threat_indicators,
)
from src.scan_email import load_model, scan_email, scan_sms


def test_eml_parsing_and_spoofing():
    print("\n--- 1. Testing EML Header Parsing & Display Name Spoofing ---")
    raw_eml = (
        "From: \"PayPal Support\" <phish-alert@malicious-account-update.xyz>\n"
        "Reply-To: credential-collector@stealer-host.top\n"
        "To: victim@example.com\n"
        "Subject: Urgent: Verify your PayPal account\n"
        "Date: Sat, 10 Oct 2026 10:00:00 +0000\n"
        "Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail\n"
        "\n"
        "Dear Customer, click here to verify your identity within 24 hours: http://paypa1-security.xyz/login\n"
    )

    header_info = parse_eml_content(raw_eml)
    assert header_info["from_name"] == "PayPal Support"
    assert "malicious-account-update.xyz" in header_info["from_email"]
    assert "Urgent: Verify your PayPal account" in header_info["subject"]
    assert "credential-collector@stealer-host.top" in header_info["reply_to"]
    print("✅ parse_eml_content extracted all RFC 822 fields successfully.")

    alerts = analyze_email_headers(header_info)
    assert len(alerts) >= 3, f"Expected at least 3 alerts, got {len(alerts)}"
    
    spoof_alert = any(a["type"] == "display_name_spoofing" for a in alerts)
    reply_to_alert = any(a["type"] == "reply_to_mismatch" for a in alerts)
    spf_alert = any(a["type"] == "spf_fail" for a in alerts)
    dkim_alert = any(a["type"] == "dkim_fail" for a in alerts)

    assert spoof_alert, "Failed to catch display name spoofing"
    assert reply_to_alert, "Failed to catch Reply-To mismatch"
    assert spf_alert, "Failed to catch SPF failure"
    assert dkim_alert, "Failed to catch DKIM failure"
    print("✅ analyze_email_headers caught display spoofing, Reply-To mismatch, and auth failures.")


def test_homoglyphs_and_typosquatting():
    print("\n--- 2. Testing Homoglyphs & Typosquatting Analysis ---")
    # Cyrillic 'а' (\u0430) spoofing 'paypal.com'
    cyrillic_domain = "p\u0430ypal.com"
    homoglyphs = detect_homoglyphs(cyrillic_domain)
    assert len(homoglyphs) > 0, "Failed to detect Cyrillic homoglyph in domain"
    print(f"✅ Homoglyph detected: {homoglyphs[0]}")

    # Punycode check
    punycode_domain = "xn--pypal-4ve.com"
    puny_flags = detect_homoglyphs(punycode_domain)
    assert any("Punycode" in f for f in puny_flags), "Failed to detect Punycode domain"
    print("✅ Punycode detection passed.")

    # Typosquatting checks (paypa1, wellsfarg0, etc.)
    typosquat_flags = check_typosquatting("paypa1.com")
    assert any("typosquatting" in f for f in typosquat_flags), "Failed to detect typosquatting in paypa1.com"
    print("✅ Levenshtein distance typosquatting passed for 'paypa1.com'.")

    # Deceptive subdomain injection
    brand_subdomain_flags = check_typosquatting("paypal.com.verify-billing.xyz")
    assert any("Deceptive brand" in f for f in brand_subdomain_flags), "Failed to detect brand injection"
    print("✅ Deceptive brand subdomain injection passed.")


def test_token_highlight_spans():
    print("\n--- 3. Testing Token Highlight Span Extraction ---")
    text = "URGENT: Your account has been suspended! Click here to verify your identity now: http://fake-bank.xyz"
    spans = extract_threat_spans(text, is_sms=False)

    assert len(spans) >= 3, f"Expected at least 3 spans, got {len(spans)}"
    categories = [s["category"] for s in spans]
    assert "urgency" in categories
    assert "credential" in categories
    assert "url" in categories

    # Verify no overlaps
    for i in range(len(spans) - 1):
        assert spans[i]["end"] <= spans[i+1]["start"], f"Span overlap found between {spans[i]} and {spans[i+1]}"

    print(f"✅ Highlight spans generated without overlaps ({len(spans)} spans matched).")


def test_sms_model_consistency():
    print("\n--- 4. Testing SMS Preprocessing & Classification ---")
    model = load_model()
    sms_threat = "FREE MSG: Congratulations you won $1000 Walmart Gift Card! Claim now at http://win-claim.top"
    sms_res = scan_sms(model, sms_threat)
    assert sms_res["is_spam_or_phishing"] is True, "Failed to flag spam SMS"
    assert sms_res["confidence"] > 90, "Confidence should be high on prize scam"
    print(f"✅ SMS scan classified correctly: Threat={sms_res['is_spam_or_phishing']} ({sms_res['confidence']}%)")


def run_all():
    print("=" * 65)
    print(" RUNNING INBOXSENTINEL THREAT FORENSICS TEST SUITE")
    print("=" * 65)
    test_eml_parsing_and_spoofing()
    test_homoglyphs_and_typosquatting()
    test_token_highlight_spans()
    test_sms_model_consistency()
    print("\n🎉 ALL FORENSICS & PARSING TESTS PASSED SUCCESSFULLY!\n")


if __name__ == "__main__":
    run_all()
