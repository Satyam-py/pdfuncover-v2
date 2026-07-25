# modules/threat_intel/providers/abuseipdb.py
"""
AbuseIPDB provider, following the same conventions as the VirusTotal
and OTX providers (modules/threat_intel/providers/virustotal.py,
modules/threat_intel/providers/otx.py).

AbuseIPDB only supports IP reputation lookups, so only lookup_ip() is
implemented. Raw AbuseIPDB JSON never leaves this module — every
field is normalized into ThreatIntelResult / ReputationFinding /
IPContext before being returned.

AbuseIPDB's core signal is abuseConfidenceScore (0-100), not an
AV-style detection count. It is normalized onto the existing
ReputationFinding fields:
    - malicious / total  -> abuseConfidenceScore / 100, so it still
                            renders as a ratio
    - reputation          -> the raw abuseConfidenceScore
    - threat_names        -> distinct abuse report categories seen
                             across recent reports
    - categories          -> usage type, ISP, Tor exit flag, and
                             whitelist status
A confidence score of 0 with no reports still produces a successful
ProviderResult with a populated (all-zero) ReputationFinding — never
an error.
"""

import logging
import os

import requests

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    ReputationFinding,
    IPContext,
    LookupError,
)

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

PROVIDER_NAME = "AbuseIPDB"

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 20
_MAX_AGE_DAYS = 90

# AbuseIPDB numeric report category codes considered notable enough to
# surface as a distinct "threat name" label when seen in recent reports.
_CATEGORY_LABELS = {
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


# ==========================================
# HTTP HELPER
# ==========================================

def _headers(api_key):
    return {"Key": api_key, "Accept": "application/json"}


def _request(ip, api_key):
    """
    Perform a single AbuseIPDB API GET request.
    Returns (json_dict, LookupError) — exactly one of the two is None.
    """

    params = {"ipAddress": ip, "maxAgeInDays": _MAX_AGE_DAYS}

    try:
        r = requests.get(
            _BASE_URL, headers=_headers(api_key), params=params, timeout=_TIMEOUT
        )

    except requests.exceptions.Timeout:
        return None, LookupError.NETWORK_ERROR

    except requests.exceptions.RequestException as e:
        log.error(f"AbuseIPDB request failed: {e}")
        return None, LookupError.NETWORK_ERROR

    if r.status_code == 404:
        return None, LookupError.NOT_FOUND

    if r.status_code in (401, 403):
        return None, LookupError.AUTH_ERROR

    if r.status_code == 429:
        return None, LookupError.RATE_LIMITED

    if r.status_code >= 400:
        return None, LookupError.UNKNOWN

    try:
        return r.json(), None

    except ValueError as e:
        log.error(f"AbuseIPDB response JSON parse failed: {e}")
        return None, LookupError.PARSE_ERROR


# ==========================================
# NORMALIZATION HELPERS
# ==========================================

def _report_category_labels(reports):
    """Distinct, human-readable labels for abuse categories seen in recent reports."""

    labels = []

    for report in reports or []:
        for code in report.get("categories") or []:
            label = _CATEGORY_LABELS.get(code)
            if label and label not in labels:
                labels.append(label)

    return labels


def _build_categories(attributes):
    categories = []

    usage_type = attributes.get("usageType")
    if usage_type:
        categories.append(f"Usage type: {usage_type}")

    isp = attributes.get("isp")
    if isp:
        categories.append(f"ISP: {isp}")

    if attributes.get("isTor"):
        categories.append("Tor exit node")

    if attributes.get("isWhitelisted"):
        categories.append("Whitelisted")

    return categories


# ==========================================
# IP
# ==========================================

def lookup_ip(ip, api_key):
    """Look up an IP's AbuseIPDB abuse report history."""

    ioc = Ioc(value=ip, type=IocType.IP)

    data, err = _request(ip, api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    attributes = data.get("data", {}) or {}

    score = attributes.get("abuseConfidenceScore", 0) or 0
    reports = attributes.get("reports", []) or []

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=score,
        suspicious=0,
        harmless=0,
        undetected=0,
        total=100,
        reputation=score,
        categories=_build_categories(attributes),
        threat_names=_report_category_labels(reports),
        permalink=f"https://www.abuseipdb.com/check/{ip}",
    )

    ip_context = IPContext(
        asn=None,
        organization=attributes.get("isp"),
        country=attributes.get("countryCode"),
        network=attributes.get("domain"),
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, ip_context=ip_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)