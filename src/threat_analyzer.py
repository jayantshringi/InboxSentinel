"""
InboxSentinel Threat Indicator Analyzer

Heuristic rule engine that extracts and highlights phishing, spam, and smishing
indicators (urgency phrases, financial lures, credential harvesting keywords,
suspicious URLs/domains, and risk factor scoring).
"""
import re
from urllib.parse import urlparse

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
    "cf", "gq", "work", "cam", "icu", "rest", "fit", "bar", "live", "surf"
}


def extract_urls(text):
    """Find all URLs in the text and analyze potential risk."""
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
            
            # IP address instead of domain name
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                flags.append("Direct IP address host (high phishing risk)")
                
            # Suspicious TLD check
            tld = host.split(".")[-1] if "." in host else ""
            if tld in SUSPICIOUS_TLDS:
                flags.append(f"Suspicious/uncommon TLD (.{tld})")
                
            # Deceptive banking / login subdomains
            deceptive_keywords = ["bank", "login", "verify", "secure", "signin", "account", "update", "paypal", "apple", "netflix"]
            for kw in deceptive_keywords:
                if kw in host and not (host.endswith(f"{kw}.com") or host == f"{kw}.com"):
                    flags.append(f"Suspicious branding keywords in domain ('{kw}')")
                    break

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


def analyze_threat_indicators(text, is_sms=False):
    """
    Examines text for known threat indicators and returns a structured analysis.
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
            "summary": "No content detected to inspect."
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

    # Calculate heuristic score (0 - 100)
    score = 0
    score += len(urgency_found) * 20
    score += len(financial_found) * 25
    score += len(credential_found) * 25
    score += len(smishing_found) * 25
    score += len(urls) * 15
    score += suspicious_url_count * 30

    # Cap score at 100
    score = min(100, score)

    # Determine risk level
    if score >= 70 or (len(credential_found) > 0 and len(urgency_found) > 0):
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

    if threat_reasons:
        summary = f"Flagged with {len(threat_reasons)} distinct threat indicators: " + "; ".join(threat_reasons) + "."
    else:
        summary = "No overt phishing or scam keywords detected in heuristic rule-set."

    return {
        "urgency_triggers": urgency_found,
        "financial_triggers": financial_found,
        "credential_triggers": credential_found,
        "smishing_triggers": smishing_found,
        "urls": urls,
        "indicator_score": score,
        "risk_level": risk_level,
        "summary": summary
    }
