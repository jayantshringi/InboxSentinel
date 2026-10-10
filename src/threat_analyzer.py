"""
InboxSentinel Threat Indicator & Forensic Analyzer

Comprehensive heuristic and forensic analysis engine:
- Natural Language Threat Indicators (urgency, credential harvesting, financial lures, smishing)
- URL & Domain Forensics (suspicious TLDs, IP hosts, homoglyphs, Punycode, typosquatting)
- Email Header Forensics (.EML parsing, display name spoofing, Reply-To mismatch, SPF/DKIM checks)
- Precise Token Span Extraction for interactive UI threat highlighting
"""
import re
import email
from email import policy
from urllib.parse import urlparse

# Target brands commonly spoofed in phishing/smishing attacks
TARGET_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "wellsfargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "irs": ["irs.gov"],
}

# Unicode homoglyphs commonly used in deceptive lookalike URLs (Cyrillic, Greek, etc.)
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    '\u0491': 'g', '\u04bb': 'h', '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u',
    '\u03bd': 'v', '\u0251': 'a', '\u0261': 'g', '\u0131': 'i',
}

# Urgency & Coercion triggers
URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediat(e|ely)\b",
    r"\baction\s+required\b",
    r"\bwithin\s+\d+\s+(hours?|mins?|minutes?|days?)\b",
    r"\baccount\s+(has\s+been\s+)?(suspended|locked|terminated|deactivated|closed|restricted)\b",
    r"\bsecurity\s+alert\b",
    r"\bunauthorized\s+access\b",
    r"\bverify\s+your\s+identity\b",
    r"\bverify\s+your\s+account\b",
    r"\bfinal\s+notice\b",
    r"\bdeadline\b",
    r"\bexpires?\s+today\b",
    r"\bimmediate\s+response\b",
    r"\blast\s+chance\b",
    r"\btime\s+is\s+running\s+out\b",
    r"\battention\s+needed\b",
    r"\bsuspended\s+immediately\b",
    r"\b24\s+hours\s+to\s+respond\b",
]

# Financial lures & prize scam triggers
FINANCIAL_PATTERNS = [
    r"\b(crypto|bitcoin|btc|eth|ethereum)\b",
    r"\blottery\b",
    r"\bwinner\b",
    r"\bwon\s+(\$|usd|inr|gbp|eur|\d+)",
    r"\bfree\s+(money|prize|gift|reward|cash|voucher|grant|bonus)\b",
    r"\bclaim\s+(your\s+)?(prize|reward|gift|refund|funds|cash|bonus)\b",
    r"\binheritance\b",
    r"\bnigerian\s+prince\b",
    r"\bwire\s+transfer\b",
    r"\bmillion(s)?\s+(dollars|usd)?\b",
    r"\bcommission\b",
    r"\bget\s+rich\s+quick\b",
    r"\b(1000%|500%|200%|guaranteed)\s+returns?\b",
    r"\bcompensation\s+funds?\b",
    r"\bbeneficiary\b",
    r"\bunclaimed\s+(funds|assets|money|prize)\b",
    r"\binvoice\s+overdue\b",
    r"\bbank\s+details\b",
    r"\boverdue\s+payment\b",
]

# Credential harvesting & spoofing phrases
CREDENTIAL_PATTERNS = [
    r"\bclick\s+here\s+to\s+(verify|login|log\s+in|confirm|update|claim|access)\b",
    r"\bconfirm\s+your\s+(password|identity|pin|ssn|social\s+security|credentials|details)\b",
    r"\bupdate\s+your\s+(billing|payment|credit\s+card|account)\b",
    r"\benter\s+your\s+(password|credentials|code|pin)\b",
    r"\breset\s+(your\s+)?password\b",
    r"\bdear\s+(valued\s+customer|customer|user|client|account\s+holder|member|sir\/madam)\b",
    r"\bkindly\s+reply\b",
    r"\bconfidential\s+(proposal|business|partnership)\b",
    r"\bclick\s+this\s+link\b",
    r"\bclick\s+the\s+link\b",
    r"\blogin\s+to\s+your\s+account\b",
    r"\bverify\s+your\s+billing\b",
]

# SMS / Smishing specific patterns
SMISHING_PATTERNS = [
    r"\bfree\s+msg\b",
    r"\btxt\s+stop\b",
    r"\bstop\s+to\s+(opt\s*out|cancel|end)\b",
    r"\breply\s+(yes|stop|claim|help)\b",
    r"\bcall\s+(now|08\d+|1-800)\b",
    r"\bparcel\s+(delivery|tracking|failed|pending|held)\b",
    r"\bpost(age|al)\s+fee\b",
    r"\bpackage\s+(waiting|delayed|delivery)\b",
    r"\bcustoms\s+fee\b",
]

# Suspicious TLDs commonly seen in spam/phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "site", "online", "loan", "tk", "ml", "ga",
    "cf", "gq", "work", "cam", "icu", "rest", "fit", "bar", "live", "surf", "cn", "ru"
}


def levenshtein_distance(s1, s2):
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_homoglyphs(domain):
    """Detect non-ASCII homoglyphs and Punycode spoofing in a domain."""
    findings = []
    # Check for Punycode
    if "xn--" in domain.lower():
        findings.append("Punycode encoded domain (frequent internationalized homoglyph disguise)")

    # Check for confusable characters
    replaced = []
    has_homoglyphs = False
    for char in domain:
        if char in HOMOGLYPH_MAP:
            has_homoglyphs = True
            replaced.append(HOMOGLYPH_MAP[char])
        else:
            replaced.append(char)

    if has_homoglyphs:
        spoofed_target = "".join(replaced)
        findings.append(f"Unicode homoglyph characters detected (imitates '{spoofed_target}')")

    return findings


def check_typosquatting(domain):
    """Check if domain appears to typosquat a well-known target brand."""
    clean_domain = domain.lower().split(":")[0]
    parts = clean_domain.split(".")
    if len(parts) < 2:
        return []

    # Get primary registered name (e.g., 'paypa1' from 'paypa1.com')
    sld = parts[-2]
    flags = []

    for brand, legit_domains in TARGET_BRANDS.items():
        if clean_domain in legit_domains:
            continue  # Legitimate domain

        # 1. Direct edit distance match (e.g., paypa1, wellsfarg0, app1e)
        dist = levenshtein_distance(sld, brand)
        if 1 <= dist <= 2 and abs(len(sld) - len(brand)) <= 1:
            flags.append(f"Potential typosquatting ({sld} mimics '{brand}')")

        # 2. Deceptive brand prefix / subdomain spoofing (e.g., paypal.com.verify.xyz)
        if brand in clean_domain and not any(clean_domain.endswith(legit) for legit in legit_domains):
            flags.append(f"Deceptive brand name injection ('{brand}' found in suspicious host)")

    return flags


def extract_urls(text):
    """Find all URLs in the text and perform thorough forensic risk analysis."""
    url_regex = r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)"
    raw_urls = re.findall(url_regex, text)
    analyzed_urls = []

    for raw in raw_urls:
        formatted = raw if raw.startswith("http") else f"http://{raw}"
        try:
            parsed = urlparse(formatted)
            netloc = parsed.netloc.lower()
            host = netloc.split(":")[0]

            flags = []
            # Insecure HTTP
            if parsed.scheme == "http":
                flags.append("Insecure HTTP protocol")

            # Direct IP address
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                flags.append("Direct IP address host (high phishing risk)")

            # Suspicious TLD check
            tld = host.split(".")[-1] if "." in host else ""
            if tld in SUSPICIOUS_TLDS:
                flags.append(f"Suspicious/uncommon TLD (.{tld})")

            # Homoglyphs and Punycode
            homoglyph_flags = detect_homoglyphs(host)
            flags.extend(homoglyph_flags)

            # Typosquatting
            typosquat_flags = check_typosquatting(host)
            flags.extend(typosquat_flags)

            # Excessively deep subdomains
            if host.count(".") > 3:
                flags.append("Excessive subdomain depth (obfuscation pattern)")

            analyzed_urls.append({
                "url": raw,
                "host": host,
                "flags": flags,
                "is_suspicious": len(flags) > 0
            })
        except Exception:
            analyzed_urls.append({
                "url": raw,
                "host": "unknown",
                "flags": ["Malformed URL structure"],
                "is_suspicious": True
            })

    return analyzed_urls


def extract_threat_spans(text, is_sms=False):
    """
    Finds exact string character offsets for highlighted UI threat tokens.
    Returns non-overlapping list of spans sorted by start position.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    spans = []

    def collect_matches(patterns, category, label):
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                spans.append({
                    "start": m.start(),
                    "end": m.end(),
                    "text": m.group(0),
                    "category": category,
                    "label": label
                })

    collect_matches(URGENCY_PATTERNS, "urgency", "Urgency Cue")
    collect_matches(FINANCIAL_PATTERNS, "financial", "Financial Lure")
    collect_matches(CREDENTIAL_PATTERNS, "credential", "Credential Trap")
    if is_sms:
        collect_matches(SMISHING_PATTERNS, "smishing", "Smishing Marker")

    # Find URLs
    url_regex = r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)"
    for m in re.finditer(url_regex, text):
        spans.append({
            "start": m.start(),
            "end": m.end(),
            "text": m.group(0),
            "category": "url",
            "label": "Web Link"
        })

    # Sort spans by start offset
    spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))

    # Remove overlapping spans (greedy keep first / longer)
    non_overlapping = []
    current_end = -1
    for span in spans:
        if span["start"] >= current_end:
            non_overlapping.append(span)
            current_end = span["end"]

    return non_overlapping


def parse_eml_content(raw_eml):
    """
    Parses raw RFC 822 / .EML text or bytes and extracts structured email forensics.
    """
    if isinstance(raw_eml, bytes):
        msg = email.message_from_bytes(raw_eml, policy=policy.default)
    else:
        msg = email.message_from_string(raw_eml, policy=policy.default)

    subject = str(msg.get("subject", "") or "")
    from_raw = str(msg.get("from", "") or "")
    to_raw = str(msg.get("to", "") or "")
    reply_to = str(msg.get("reply-to", "") or "")
    return_path = str(msg.get("return-path", "") or "")
    date_raw = str(msg.get("date", "") or "")
    auth_results = str(msg.get("authentication-results", "") or "")

    # Parse display name and email address
    parsed_from = email.utils.parseaddr(from_raw)
    from_name = parsed_from[0].strip()
    from_email = parsed_from[1].strip()

    parsed_reply_to = email.utils.parseaddr(reply_to) if reply_to else ("", "")

    # Extract body content (prefers plain text, falls back to html)
    plain_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            if ctype == "text/plain" and not plain_body:
                try:
                    plain_body = part.get_content()
                except Exception:
                    plain_body = part.get_payload(decode=True).decode(errors="replace")
            elif ctype == "text/html" and not html_body:
                try:
                    html_body = part.get_content()
                except Exception:
                    html_body = part.get_payload(decode=True).decode(errors="replace")
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = msg.get_payload(decode=True).decode(errors="replace")
        if msg.get_content_type() == "text/html":
            html_body = content
        else:
            plain_body = content

    # Clean HTML to plain text fallback if needed
    final_body = plain_body
    if not final_body and html_body:
        final_body = re.sub(r"<style.*?>.*?</style>", " ", html_body, flags=re.DOTALL)
        final_body = re.sub(r"<script.*?>.*?</script>", " ", final_body, flags=re.DOTALL)
        final_body = re.sub(r"<.*?>", " ", final_body, flags=re.DOTALL)
        final_body = re.sub(r"\s+", " ", final_body).strip()

    full_text = f"{subject}\n\n{final_body}".strip() if subject else final_body.strip()

    header_info = {
        "subject": subject,
        "from_raw": from_raw,
        "from_name": from_name,
        "from_email": from_email,
        "to_raw": to_raw,
        "reply_to": parsed_reply_to[1] if parsed_reply_to[1] else "",
        "return_path": return_path,
        "date": date_raw,
        "auth_results": auth_results,
        "extracted_body": final_body,
        "full_text": full_text
    }

    return header_info


def analyze_email_headers(header_info):
    """
    Forensic analysis of email headers:
    - Display Name Spoofing / Impersonation
    - From vs Reply-To domain mismatch
    - SPF / DKIM / DMARC authentication check
    """
    alerts = []
    from_name = header_info.get("from_name", "").lower()
    from_email = header_info.get("from_email", "").lower()
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    reply_to = header_info.get("reply_to", "").lower()
    reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else ""
    auth_results = header_info.get("auth_results", "").lower()

    # 1. Display Name Impersonation Check
    for brand, legit_domains in TARGET_BRANDS.items():
        if brand in from_name:
            if from_domain and not any(from_domain.endswith(legit) for legit in legit_domains):
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "display_name_spoofing",
                    "message": f"Display Name impersonates '{brand.title()}' but is sent from unauthorized domain '@{from_domain}'."
                })
                break

    # 2. Reply-To Domain Mismatch
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        alerts.append({
            "severity": "HIGH",
            "type": "reply_to_mismatch",
            "message": f"Reply-To domain mismatch: replies route to '@{reply_to_domain}' instead of sender '@{from_domain}'."
        })

    # 3. Authentication Results (SPF, DKIM, DMARC)
    if auth_results:
        if "spf=fail" in auth_results or "spf=softfail" in auth_results:
            alerts.append({
                "severity": "HIGH",
                "type": "spf_fail",
                "message": "SPF authentication check failed for sender IP."
            })
        if "dkim=fail" in auth_results:
            alerts.append({
                "severity": "HIGH",
                "type": "dkim_fail",
                "message": "DKIM cryptographic signature verification failed (possible tampering)."
            })
        if "dmarc=fail" in auth_results:
            alerts.append({
                "severity": "CRITICAL",
                "type": "dmarc_fail",
                "message": "DMARC policy validation failed."
            })

    return alerts


def analyze_threat_indicators(text, is_sms=False, header_info=None):
    """
    Examines text and optional email headers for known threat indicators
    and returns a structured forensic analysis with highlighting spans.
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "urgency_triggers": [],
            "financial_triggers": [],
            "credential_triggers": [],
            "smishing_triggers": [],
            "urls": [],
            "indicator_score": 0,
            "risk_level": "CLEAN",
            "summary": "No content detected to inspect.",
            "highlight_spans": [],
            "header_alerts": []
        }

    urgency_found = []
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            urgency_found.append(match.group(0).strip())

    financial_found = []
    for pattern in FINANCIAL_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            financial_found.append(match.group(0).strip())

    credential_found = []
    for pattern in CREDENTIAL_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            credential_found.append(match.group(0).strip())

    smishing_found = []
    if is_sms:
        for pattern in SMISHING_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                smishing_found.append(match.group(0).strip())

    urls = extract_urls(text)
    suspicious_url_count = sum(1 for u in urls if u["is_suspicious"])

    # Header alerts if provided
    header_alerts = []
    if header_info:
        header_alerts = analyze_email_headers(header_info)

    # Compute heuristic forensic score (0 - 100)
    score = 0
    score += len(urgency_found) * 20
    score += len(financial_found) * 25
    score += len(credential_found) * 25
    score += len(smishing_found) * 25
    score += len(urls) * 10
    score += suspicious_url_count * 30

    # Header penalties
    for alert in header_alerts:
        if alert["severity"] == "CRITICAL":
            score += 45
        elif alert["severity"] == "HIGH":
            score += 30

    score = min(100, score)

    # Determine risk level
    if score >= 70 or any(a["severity"] == "CRITICAL" for a in header_alerts) or (len(credential_found) > 0 and len(urgency_found) > 0):
        risk_level = "CRITICAL"
    elif score >= 45:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "ELEVATED"
    elif score > 0:
        risk_level = "LOW"
    else:
        risk_level = "CLEAN"

    # Human-readable summary
    threat_reasons = []
    if urgency_found:
        threat_reasons.append(f"artificial urgency cues ({', '.join(urgency_found[:2])})")
    if credential_found:
        threat_reasons.append(f"credential verification traps ({', '.join(credential_found[:2])})")
    if financial_found:
        threat_reasons.append(f"financial or reward lures ({', '.join(financial_found[:2])})")
    if smishing_found:
        threat_reasons.append(f"smishing delivery markers ({', '.join(smishing_found[:2])})")
    if suspicious_url_count > 0:
        threat_reasons.append(f"{suspicious_url_count} high-risk URL(s)")
    if header_alerts:
        threat_reasons.append(f"{len(header_alerts)} email header spoofing alert(s)")

    if threat_reasons:
        summary = f"Flagged with {len(threat_reasons)} distinct threat indicators: " + "; ".join(threat_reasons) + "."
    else:
        summary = "No overt phishing or scam keywords detected in heuristic rule-set."

    # Highlight spans
    highlight_spans = extract_threat_spans(text, is_sms=is_sms)

    return {
        "urgency_triggers": urgency_found,
        "financial_triggers": financial_found,
        "credential_triggers": credential_found,
        "smishing_triggers": smishing_found,
        "urls": urls,
        "indicator_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "highlight_spans": highlight_spans,
        "header_alerts": header_alerts
    }
