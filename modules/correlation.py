# modules/correlation.py
"""
Threat Correlation Engine.

Takes the PDF analysis results that already exist elsewhere in the
codebase (metadata, embedded-object analysis, JavaScript analysis,
stream analysis, AcroForm analysis, compression analysis, IOCs) plus
Threat Intelligence results (modules/threat_intel.py /
modules/parsers/ioc_enrichment.py) and looks for *combinations* of
findings that are individually unremarkable but, together, indicate a
specific attack behavior — the same way a human analyst reasons about
a file, not just "this file has N red flags".

This module is intentionally standalone:
    - It does not modify, call into, or depend on analyzer.py.
    - It does not modify IOC extraction (modules/parsers/iocs.py) or
      the Threat Intelligence providers (modules/providers.py,
      modules/threat_intel.py, modules/reputation.py).
    - It does not modify report generation.
    - It is NOT wired into main.py or analyzer.py yet. It exposes a
      pure function / class that a future integration step can call;
      until then, nothing in the existing pipeline invokes this file.

Every generated finding always explains WHY it fired — title +
severity alone are never considered sufficient. Each finding carries:
    Title, Severity, Confidence, Evidence, Recommendation,
    MITRE ATT&CK (when applicable).

Input shapes expected (matching the sections already produced
elsewhere in the codebase — see modules/embedded_extraction.py and
modules/parsers/iocs.py):

    metadata               -> modules.metadata.extract_metadata() output
    embedded_analysis      -> results["Embedded Files"]   (from embedded.py)
    javascript_analysis    -> results["JavaScript"]        (from javascript.py)
    stream_analysis        -> results["Streams"]            (from streams.py)
    acroform_analysis      -> results["AcroForm"]           (from acroform.py)
    compression_analysis   -> results["Compression"]        (from compression.py)
    iocs                   -> results["IOCs"]               (from iocs.py, now
                               includes a nested "Threat Intelligence" key —
                               see modules/parsers/ioc_enrichment.py)
    threat_intelligence    -> optional; if omitted, pulled from
                               iocs["Threat Intelligence"]. May additionally
                               include a "Hashes" section (IOC-type "hash")
                               for callers that also perform hash reputation
                               lookups — this engine does not require it and
                               degrades gracefully when it's absent.

Nothing here performs new IOC extraction, new provider calls, or new
static PDF parsing beyond one narrow, explicitly-scoped exception:
hashing an already-extracted embedded file on disk (see
_hash_extracted_file()) so it can be checked against hash-reputation
data the caller may provide. That hashing is read-only, wrapped in
try/except, and never raises.
"""

import datetime
import hashlib
import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/correlation.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# SEVERITY / CONFIDENCE CONSTANTS
# ==========================================
#
# Same vocabulary used elsewhere in the codebase (modules/parsers/
# evidence.py) for consistency across the app's output, defined
# locally here (not imported) so this module has zero coupling to the
# parser/analyzer layers.

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"

SEVERITY_RANK = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

_SEVERITY_ORDER = [
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    SEVERITY_LOW, SEVERITY_INFO,
]


# ==========================================
# SCORING WEIGHTS (for "Correlation Score")
# ==========================================

_SEVERITY_WEIGHT: Dict[str, float] = {
    SEVERITY_CRITICAL: 40.0,
    SEVERITY_HIGH:      22.0,
    SEVERITY_MEDIUM:    10.0,
    SEVERITY_LOW:         3.0,
    SEVERITY_INFO:        0.0,
}

_CONFIDENCE_MULTIPLIER: Dict[str, float] = {
    CONFIDENCE_HIGH:    1.0,
    CONFIDENCE_MEDIUM:  0.65,
    CONFIDENCE_LOW:     0.35,
}

# "Half-life" of the diminishing-returns curve used to turn a raw
# weighted-finding sum into a bounded 0-100 Correlation Score — the
# same style of curve used for Risk Score elsewhere in the app, but a
# fully independent implementation (this module imports nothing from
# analyzer.py).
_CORRELATION_SCORE_HALF_LIFE = 45.0

# Malicious-URL/IP threat-intel threshold: an IOC with a reputation
# score at or above this (0-100 scale, see modules/reputation.py) is
# treated as "malicious" for correlation purposes. Between this and
# _SUSPICIOUS_SCORE_THRESHOLD it's treated as "suspicious" instead.
_MALICIOUS_SCORE_THRESHOLD = 70
_SUSPICIOUS_SCORE_THRESHOLD = 30

# Dangerous embedded-file extensions considered "executable" for the
# Embedded EXE correlation rules.
_EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".scr", ".cpl", ".com", ".bat", ".cmd",
    ".ps1", ".vbs", ".hta", ".msi",
)

# Archive extensions considered "embedded ZIP" for those rules.
_ARCHIVE_EXTENSIONS = (".zip", ".jar")

# JavaScript keywords treated as obfuscation/exploit indicators for
# the "Obfuscated JavaScript" side of a correlation. Deliberately kept
# local/minimal rather than imported from analyzer.py, per this
# module's zero-coupling design.
_JS_OBFUSCATION_KEYWORDS = frozenset({
    "eval", "unescape", "fromCharCode", "atob",
    "app.launchURL", "this.exportDataObject", "submitForm",
    "Collab.collectEmailInfo", "util.printf", "getAnnots",
})

# A small, illustrative set of frequently-impersonated brand domains,
# used only for the local typosquat heuristic below. Not exhaustive —
# real typosquat detection belongs in a dedicated provider; this is a
# best-effort signal the correlation engine can reason about today
# without requiring one.
_KNOWN_BRAND_DOMAINS = (
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "netflix.com", "chase.com",
    "bankofamerica.com", "dropbox.com", "adobe.com", "docusign.com",
    "office.com", "outlook.com", "wellsfargo.com", "linkedin.com",
    "instagram.com", "whatsapp.com", "icloud.com", "irs.gov",
)

# Domains this short a Levenshtein distance from a known brand are
# flagged as likely typosquats (e.g. "paypa1.com" is 1 from
# "paypal.com"). Kept small to avoid false positives on unrelated
# short domains.
_TYPOSQUAT_MAX_DISTANCE = 2

# Keys checked (in order) on a threat-intel provider's raw response
# when looking for a domain-age signal, for the "Newly Registered
# Domain" heuristic. Different providers name this differently (or
# don't provide it at all) — this is best-effort and simply doesn't
# fire when none of these are present.
_DOMAIN_AGE_RAW_KEYS = (
    "creation_date", "created", "domain_creation_date",
    "first_seen", "registered", "domain_age_days",
)
_NEWLY_REGISTERED_DAYS_THRESHOLD = 90


# ==========================================
# FINDING BUILDER
# ==========================================

def _finding(
    title: str,
    severity: str,
    confidence: str,
    evidence: str,
    recommendation: str,
    mitre: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build one standardized Correlated Finding. `evidence` must always
    explain WHY the finding fired (which signals combined and how) —
    this engine never emits a bare "Malicious" verdict with nothing
    to back it up.
    """

    return {
        "Title": title,
        "Severity": severity,
        "Confidence": confidence,
        "Evidence": evidence,
        "Recommendation": recommendation,
        "MITRE ATT&CK": mitre or [],
    }


# ==========================================
# SMALL GENERIC HELPERS
# ==========================================

def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts without KeyError."""

    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current


def _levenshtein(a: str, b: str) -> int:
    """Standard edit distance, used only by the typosquat heuristic."""

    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))

    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row

    return previous_row[-1]


def _hash_extracted_file(path: str) -> Optional[str]:
    """
    SHA256 of an already-extracted embedded file, for hash-reputation
    correlation. Read-only, best-effort: returns None (never raises)
    if the file is missing, unreadable, or anything else goes wrong —
    embedded.py's on-disk extractions aren't guaranteed to still exist
    by the time correlation runs.
    """

    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError as e:
        log.error(f"Could not hash extracted file {path}: {e}")
        return None


# ==========================================
# THREAT INTELLIGENCE HELPERS
# ==========================================

def _ti_verdict_for_score(score: Any) -> str:
    """Map a 0-100 reputation score to a coarse malicious/suspicious/clean bucket."""

    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"

    if score >= _MALICIOUS_SCORE_THRESHOLD:
        return "malicious"
    if score >= _SUSPICIOUS_SCORE_THRESHOLD:
        return "suspicious"
    return "clean"


def _flatten_ti_entries(
    threat_intelligence: Dict[str, Any]
) -> List[Tuple[str, str, Dict[str, Any]]]:
    """
    Flatten the nested Threat Intelligence block (see
    modules/parsers/ioc_enrichment.py) into a flat list of
    (ioc_type, ioc_value, entry) tuples, across every category
    present (URLs, Domains, IPs, and Hashes if a caller supplies it).
    """

    entries: List[Tuple[str, str, Dict[str, Any]]] = []

    if not isinstance(threat_intelligence, dict):
        return entries

    category_to_type = {
        "URLs": "url", "Domains": "domain",
        "IPs": "ip", "Hashes": "hash",
    }

    for category, ioc_type in category_to_type.items():
        section = threat_intelligence.get(category) or {}
        if not isinstance(section, dict):
            continue
        for ioc_value, entry in section.items():
            if isinstance(entry, dict):
                entries.append((ioc_type, ioc_value, entry))

    return entries


def _malicious_iocs(
    threat_intelligence: Dict[str, Any], ioc_type: str
) -> List[Tuple[str, Dict[str, Any]]]:
    """
    (ioc_value, entry) pairs of a given type whose TI verdict/score
    indicates malicious. Prefers the entry's own "verdict" field when
    present (set by modules/reputation.py); falls back to the score
    threshold above if "verdict" is missing.
    """

    results = []

    for entry_type, ioc_value, entry in _flatten_ti_entries(threat_intelligence):

        if entry_type != ioc_type:
            continue

        verdict = entry.get("verdict")
        if verdict is None:
            verdict = _ti_verdict_for_score(entry.get("score"))

        if verdict == "malicious":
            results.append((ioc_value, entry))

    return results


def _hash_intel_lookup(
    threat_intelligence: Dict[str, Any], file_hash: str
) -> Optional[Dict[str, Any]]:
    """Look up a specific hash in threat_intelligence["Hashes"], if present."""

    hashes = (threat_intelligence or {}).get("Hashes") or {}
    if not isinstance(hashes, dict):
        return None
    return hashes.get(file_hash)


# ==========================================
# DOMAIN HEURISTICS (best-effort, self-contained)
# ==========================================

def _is_typosquat(domain: str) -> Optional[str]:
    """
    Return the brand domain this looks like a typosquat of, or None.
    Exact matches to a known brand are not typosquats (that IS the
    brand) — only close-but-not-exact matches count.
    """

    domain = (domain or "").lower().strip(".")

    for brand in _KNOWN_BRAND_DOMAINS:
        if domain == brand:
            continue
        if _levenshtein(domain, brand) <= _TYPOSQUAT_MAX_DISTANCE:
            return brand

    return None


def _looks_newly_registered(threat_intelligence: Dict[str, Any], ioc_value: str) -> bool:
    """
    Best-effort check of a domain's TI data for a domain-age signal.
    Reads creation_date from the typed EnrichmentResult's DomainContext,
    which is where WHOIS, RDAP, and VirusTotal all store it after
    normalisation. Falls back to the legacy flat entry's providers dict
    for any pre-typed data. Returns True only when a creation date is
    found and falls within _NEWLY_REGISTERED_DAYS_THRESHOLD days of now.
    """

    # --- Typed path (primary): DomainContext.creation_date ---
    typed_block = (threat_intelligence or {}).get("_typed") or {}
    typed_domains = typed_block.get("Domains") if isinstance(typed_block, dict) else None
    if isinstance(typed_domains, dict):
        enrichment = typed_domains.get(ioc_value)
        if enrichment is not None:
            result = getattr(enrichment, "result", None)
            domain_ctx = getattr(result, "domain_context", None) if result is not None else None
            creation_date_str = getattr(domain_ctx, "creation_date", None) if domain_ctx is not None else None
            if creation_date_str:
                age_days = _parse_creation_date_to_age_days(str(creation_date_str))
                if age_days is not None and age_days <= _NEWLY_REGISTERED_DAYS_THRESHOLD:
                    return True

    # --- Legacy path (fallback): entry["providers"][name]["raw"] ---
    legacy_domains = (threat_intelligence or {}).get("Domains") or {}
    entry = legacy_domains.get(ioc_value) if isinstance(legacy_domains, dict) else None
    if isinstance(entry, dict):
        for provider_name, provider_detail in (entry.get("providers") or {}).items():
            raw = provider_detail.get("raw") if isinstance(provider_detail, dict) else None
            if not isinstance(raw, dict):
                continue
            for key in _DOMAIN_AGE_RAW_KEYS:
                if key not in raw:
                    continue
                value = raw[key]
                if key == "domain_age_days":
                    try:
                        if float(value) <= _NEWLY_REGISTERED_DAYS_THRESHOLD:
                            return True
                    except (TypeError, ValueError):
                        continue

    return False


def _parse_creation_date_to_age_days(creation_date_str: str) -> Optional[float]:
    """
    Parse a domain creation date string into an age in days from now.
    Handles two formats produced by the providers:
      - Unix timestamp integer as a string (VirusTotal)
      - ISO 8601 / RFC 3339 date string (WHOIS, RDAP)
    Returns None if the string cannot be parsed.
    """

    now = datetime.datetime.now(datetime.timezone.utc)

    # Unix timestamp (VirusTotal stores creation_date as an integer epoch value)
    try:
        ts = float(creation_date_str)
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return (now - dt).days
    except (ValueError, OSError, OverflowError):
        pass

    # ISO 8601 / RFC 3339 strings from WHOIS and RDAP, e.g.:
    #   "2024-03-15T10:22:00Z", "2024-03-15T10:22:00+00:00", "2024-03-15"
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.datetime.strptime(creation_date_str[:len(fmt)], fmt)
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            return (now - dt).days
        except ValueError:
            continue

    return None


# ==========================================
# CORRELATION RULES
# ==========================================
#
# Each rule below inspects a specific combination of already-computed
# findings and, if (and only if) that combination is actually present,
# returns one Correlated Finding explaining what fired and why. A rule
# returning None means "this combination wasn't observed" — it is
# never a substitute for a bare "malicious" verdict.

def _rule_openaction_malicious_url(
    javascript_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    if not javascript_analysis.get("OpenAction Found"):
        return None

    malicious_urls = _malicious_iocs(threat_intelligence, "url")
    if not malicious_urls:
        return None

    url_list = ", ".join(u for u, _ in malicious_urls[:3])
    more = f" (+{len(malicious_urls) - 3} more)" if len(malicious_urls) > 3 else ""

    return _finding(
        title="Automatic Action Launches a Known-Malicious URL",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        evidence=(
            f"An /OpenAction trigger fires automatically when the document "
            f"is opened, and the document also references a URL flagged as "
            f"malicious by threat intelligence: {url_list}{more}. Combined, "
            f"these mean the malicious destination can be reached without "
            f"any user interaction."
        ),
        recommendation=(
            "Do not open this file outside an isolated sandbox. Identify "
            "exactly what /OpenAction invokes and block the flagged URL(s) "
            "at the network layer before any further handling."
        ),
        mitre=["T1204.002", "T1071.001"],
    )


def _rule_embedded_exe_malware_hash(
    embedded_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    for path in embedded_analysis.get("Extracted Files", []) or []:

        ext = os.path.splitext(path.lower())[1]
        if ext not in _EXECUTABLE_EXTENSIONS:
            continue

        file_hash = _hash_extracted_file(path)
        if not file_hash:
            continue

        hash_entry = _hash_intel_lookup(threat_intelligence, file_hash)
        if not hash_entry:
            continue

        verdict = hash_entry.get("verdict") or _ti_verdict_for_score(hash_entry.get("score"))
        if verdict != "malicious":
            continue

        return _finding(
            title="Embedded Executable Matches a Known Malware Hash",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence=(
                f"'{os.path.basename(path)}' ({ext}) was extracted from the "
                f"PDF and its SHA256 ({file_hash}) matches a hash already "
                f"known to threat intelligence as malicious."
            ),
            recommendation=(
                "Treat this file as confirmed malware. Isolate the source "
                "PDF immediately, do not execute the extracted file, and "
                "escalate to incident response."
            ),
            mitre=["T1204.002", "T1105"],
        )

    return None


def _rule_obfuscated_js_malicious_url(
    javascript_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    keywords = [
        k for k in (javascript_analysis.get("Suspicious Keywords") or [])
        if k in _JS_OBFUSCATION_KEYWORDS
    ]

    if not keywords:
        return None

    malicious_urls = _malicious_iocs(threat_intelligence, "url")
    if not malicious_urls:
        return None

    url_list = ", ".join(u for u, _ in malicious_urls[:3])
    more = f" (+{len(malicious_urls) - 3} more)" if len(malicious_urls) > 3 else ""

    return _finding(
        title="Obfuscated JavaScript Alongside a Known-Malicious URL",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        evidence=(
            f"JavaScript in this document uses obfuscation/exploit-prone "
            f"API calls ({', '.join(keywords)}), and the document also "
            f"references a URL already flagged as malicious: "
            f"{url_list}{more}. Obfuscation is commonly used to hide the "
            f"logic that reaches out to exactly this kind of destination."
        ),
        recommendation=(
            "Manually decode the JavaScript to confirm what it does with "
            "the flagged URL (fetch, redirect, exfiltration, etc.) before "
            "this file is opened by anyone."
        ),
        mitre=["T1027", "T1204.002", "T1071.001"],
    )


def _rule_high_entropy_stream_malware_hash(
    stream_analysis: Dict[str, Any],
    embedded_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    high_entropy = stream_analysis.get("High Entropy Streams") or []
    if not high_entropy:
        return None

    for path in embedded_analysis.get("Extracted Files", []) or []:

        file_hash = _hash_extracted_file(path)
        if not file_hash:
            continue

        hash_entry = _hash_intel_lookup(threat_intelligence, file_hash)
        if not hash_entry:
            continue

        verdict = hash_entry.get("verdict") or _ti_verdict_for_score(hash_entry.get("score"))
        if verdict != "malicious":
            continue

        return _finding(
            title="High-Entropy Stream Alongside a Known-Malicious Payload",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_MEDIUM,
            evidence=(
                f"{len(high_entropy)} stream(s) in this document show "
                f"entropy consistent with packed/encrypted content, and a "
                f"separately extracted file ('{os.path.basename(path)}', "
                f"SHA256 {file_hash}) matches a known-malicious hash. "
                f"Together these suggest the high-entropy stream(s) are "
                f"part of the same delivery mechanism."
            ),
            recommendation=(
                "Decompress and inspect the flagged stream(s) directly; "
                "treat the extracted file as confirmed malware and escalate "
                "to incident response."
            ),
            mitre=["T1027.002", "T1105"],
        )

    return None


def _rule_newly_registered_domain_javascript(
    javascript_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    if not javascript_analysis.get("JavaScript Detected"):
        return None

    for ioc_type, ioc_value, entry in _flatten_ti_entries(threat_intelligence):
        if ioc_type != "domain":
            continue
        if _looks_newly_registered(threat_intelligence, ioc_value):
            return _finding(
                title="JavaScript Referencing a Newly Registered Domain",
                severity=SEVERITY_HIGH,
                confidence=CONFIDENCE_MEDIUM,
                evidence=(
                    f"The document contains embedded JavaScript, and "
                    f"references the domain '{ioc_value}', which threat "
                    f"intelligence data indicates was registered very "
                    f"recently (within roughly "
                    f"{_NEWLY_REGISTERED_DAYS_THRESHOLD} days). Freshly "
                    f"registered domains combined with active scripting are "
                    f"a common pattern for short-lived phishing/malware "
                    f"infrastructure."
                ),
                recommendation=(
                    "Treat the domain as unproven infrastructure. Hold the "
                    "JavaScript for manual review before allowing any "
                    "network access to it."
                ),
                mitre=["T1583.001", "T1059.007"],
            )

    return None


def _rule_typosquat_domain_openaction(
    javascript_analysis: Dict[str, Any],
    iocs: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    if not javascript_analysis.get("OpenAction Found"):
        return None

    for domain in iocs.get("Domains", []) or []:

        brand = _is_typosquat(domain)

        if brand:
            return _finding(
                title="Auto-Executing Action Alongside a Typosquat Domain",
                severity=SEVERITY_HIGH,
                confidence=CONFIDENCE_MEDIUM,
                evidence=(
                    f"The document references '{domain}', which closely "
                    f"resembles the legitimate domain '{brand}' (edit "
                    f"distance <= {_TYPOSQUAT_MAX_DISTANCE}) and is "
                    f"consistent with a typosquat used for brand "
                    f"impersonation. The document also contains an "
                    f"/OpenAction trigger that fires automatically on open."
                ),
                recommendation=(
                    "Verify '{}' is not the intended legitimate domain "
                    "before proceeding. Identify what /OpenAction targets "
                    "and block the typosquat domain at the network layer."
                ).format(domain),
                mitre=["T1583.001", "T1204.002"],
            )

    return None


def _rule_encrypted_pdf_embedded_files(
    metadata: Dict[str, Any],
    embedded_analysis: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    encrypted_flag = str(metadata.get("Encrypted", "")).strip().lower()
    is_encrypted = encrypted_flag in ("yes", "true", "1")

    if not is_encrypted:
        return None

    extracted = embedded_analysis.get("Extracted Files") or []
    if not extracted:
        return None

    return _finding(
        title="Encrypted PDF Carrying Embedded Files",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        evidence=(
            f"This PDF is encrypted and also carries {len(extracted)} "
            f"embedded file(s). Encryption is routine in ordinary business "
            f"documents, but it also hinders static/AV scanning of "
            f"whatever the embedded files actually contain — the "
            f"combination is worth a closer look even though neither "
            f"signal alone is unusual."
        ),
        recommendation=(
            "Attempt to open with an empty password; if successful, "
            "re-scan the decrypted copy and inspect the embedded files "
            "directly."
        ),
        mitre=["T1027"],
    )


def _rule_embedded_zip_malware_hash(
    embedded_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    for path in embedded_analysis.get("Extracted Files", []) or []:

        ext = os.path.splitext(path.lower())[1]
        if ext not in _ARCHIVE_EXTENSIONS:
            continue

        file_hash = _hash_extracted_file(path)
        if not file_hash:
            continue

        hash_entry = _hash_intel_lookup(threat_intelligence, file_hash)
        if not hash_entry:
            continue

        verdict = hash_entry.get("verdict") or _ti_verdict_for_score(hash_entry.get("score"))
        if verdict != "malicious":
            continue

        return _finding(
            title="Embedded Archive Matches a Known Malware Hash",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence=(
                f"'{os.path.basename(path)}' ({ext}) was extracted from the "
                f"PDF and its SHA256 ({file_hash}) matches a hash already "
                f"known to threat intelligence as malicious. Archives are a "
                f"common wrapper used to smuggle a payload past simple "
                f"extension-based filters."
            ),
            recommendation=(
                "Treat this archive as confirmed malware. Do not extract or "
                "open its contents outside an isolated sandbox; escalate to "
                "incident response."
            ),
            mitre=["T1204.002", "T1105", "T1027"],
        )

    return None


def _rule_multiple_malicious_urls(
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    malicious_urls = _malicious_iocs(threat_intelligence, "url")

    if len(malicious_urls) < 2:
        return None

    url_list = ", ".join(u for u, _ in malicious_urls[:5])
    more = f" (+{len(malicious_urls) - 5} more)" if len(malicious_urls) > 5 else ""

    return _finding(
        title="Multiple Independently-Flagged Malicious URLs",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        evidence=(
            f"{len(malicious_urls)} distinct URLs referenced in this "
            f"document are independently flagged as malicious by threat "
            f"intelligence: {url_list}{more}. Multiple corroborating "
            f"malicious references raise confidence well above what any "
            f"single flagged URL would justify on its own."
        ),
        recommendation=(
            "Block all flagged URLs/domains at the network layer and treat "
            "the document as part of an active campaign rather than an "
            "isolated incident."
        ),
        mitre=["T1071.001"],
    )


def _rule_malicious_ip_and_url(
    threat_intelligence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:

    malicious_ips = _malicious_iocs(threat_intelligence, "ip")
    malicious_urls = _malicious_iocs(threat_intelligence, "url")

    if not malicious_ips or not malicious_urls:
        return None

    ip_list = ", ".join(i for i, _ in malicious_ips[:3])
    url_list = ", ".join(u for u, _ in malicious_urls[:3])

    return _finding(
        title="Corroborated Malicious Network Infrastructure",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        evidence=(
            f"This document references both a malicious IP address "
            f"({ip_list}) and a malicious URL ({url_list}) as flagged by "
            f"threat intelligence. A hardcoded malicious IP alongside a "
            f"malicious URL is stronger corroboration of live C2/"
            f"exfiltration infrastructure than either indicator alone."
        ),
        recommendation=(
            "Block the flagged IP(s) and URL(s) at the firewall/proxy and "
            "treat this file as part of an active network-based attack "
            "chain."
        ),
        mitre=["T1071.001", "T1204.002"],
    )


# ==========================================
# OVERALL IOC REPUTATION
# ==========================================

def _build_overall_ioc_reputation(threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aggregate every IOC's individual threat-intel verdict into one
    summary view: how many IOCs were checked, how many came back
    malicious/suspicious/clean/unknown, and an overall confidence that
    is boosted when multiple IOCs independently corroborate each
    other (see _rule_multiple_malicious_urls / _rule_malicious_ip_and_url
    for the corresponding correlated findings).
    """

    entries = _flatten_ti_entries(threat_intelligence)

    total = len(entries)
    malicious = suspicious = clean = unknown = 0
    scores: List[float] = []

    for _, _, entry in entries:

        verdict = entry.get("verdict") or _ti_verdict_for_score(entry.get("score"))

        if verdict == "malicious":
            malicious += 1
        elif verdict == "suspicious":
            suspicious += 1
        elif verdict == "clean":
            clean += 1
        else:
            unknown += 1

        try:
            scores.append(float(entry.get("score", 0)))
        except (TypeError, ValueError):
            pass

    highest_score = int(max(scores)) if scores else 0
    average_score = int(round(sum(scores) / len(scores))) if scores else 0

    if total == 0:
        overall_verdict = "unknown"
    elif malicious > 0:
        overall_verdict = "malicious"
    elif suspicious > 0:
        overall_verdict = "suspicious"
    else:
        overall_verdict = "clean"

    # Confidence: no data -> None. A single malicious/suspicious hit is
    # Medium at best. Multiple independent malicious hits (corroboration)
    # push this to High.
    if total == 0:
        confidence = "None"
    elif malicious >= 2:
        confidence = CONFIDENCE_HIGH
    elif malicious == 1 or suspicious >= 2:
        confidence = CONFIDENCE_MEDIUM
    else:
        confidence = CONFIDENCE_LOW

    return {
        "Total IOCs Checked": total,
        "Malicious": malicious,
        "Suspicious": suspicious,
        "Clean": clean,
        "Unknown": unknown,
        "Highest Risk Score": highest_score,
        "Average Risk Score": average_score,
        "Overall Verdict": overall_verdict,
        "Confidence": confidence,
    }


# ==========================================
# CORRELATION SCORE
# ==========================================

def _calculate_correlation_score(findings: List[Dict[str, Any]]) -> int:
    """
    0-100 score derived purely from the Correlated Findings generated
    above (NOT the same as, and independent from, analyzer.py's Risk
    Score). Weighted by severity x confidence, passed through a
    diminishing-returns curve so several corroborating High findings
    don't trivially outscore one confirmed Critical finding.
    """

    if not findings:
        return 0

    raw = sum(
        _SEVERITY_WEIGHT.get(f["Severity"], 0.0)
        * _CONFIDENCE_MULTIPLIER.get(f["Confidence"], 0.5)
        for f in findings
    )

    if raw <= 0:
        return 0

    score = 100.0 * (1.0 - math.exp(-raw / _CORRELATION_SCORE_HALF_LIFE))

    return int(round(min(100.0, max(0.0, score))))


# ==========================================
# MAIN ENTRY POINT
# ==========================================

class ThreatCorrelationEngine:
    """
    Stateless engine that cross-references already-computed PDF
    analysis results with Threat Intelligence results to synthesize
    higher-confidence, cross-signal Correlated Findings.

    Usage:
        engine = ThreatCorrelationEngine()
        result = engine.correlate(
            metadata=metadata,
            embedded_analysis=embedded_results["Embedded Files"],
            javascript_analysis=embedded_results["JavaScript"],
            stream_analysis=embedded_results["Streams"],
            acroform_analysis=embedded_results["AcroForm"],
            compression_analysis=embedded_results["Compression"],
            iocs=embedded_results["IOCs"],
        )

    Not currently called from anywhere in the pipeline (see module
    docstring) — this is the standalone engine only.
    """

    def correlate(
        self,
        metadata: Optional[Dict[str, Any]] = None,
        embedded_analysis: Optional[Dict[str, Any]] = None,
        javascript_analysis: Optional[Dict[str, Any]] = None,
        stream_analysis: Optional[Dict[str, Any]] = None,
        acroform_analysis: Optional[Dict[str, Any]] = None,
        compression_analysis: Optional[Dict[str, Any]] = None,
        iocs: Optional[Dict[str, Any]] = None,
        threat_intelligence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run every correlation rule and return:
            {
                "Overall IOC Reputation": {...},
                "Correlated Findings": [...],
                "Correlation Score": int,
            }

        Every argument is optional and defaults to an empty dict, so a
        caller that doesn't yet have every analysis section available
        still gets a valid (possibly mostly-empty) result rather than
        an exception. A single rule raising unexpectedly is caught and
        logged so it can never take down the whole correlation pass.
        """

        metadata = metadata or {}
        embedded_analysis = embedded_analysis or {}
        javascript_analysis = javascript_analysis or {}
        stream_analysis = stream_analysis or {}
        acroform_analysis = acroform_analysis or {}
        compression_analysis = compression_analysis or {}
        iocs = iocs or {}

        if threat_intelligence is None:
            threat_intelligence = iocs.get("Threat Intelligence") or {}

        rule_calls = [
            lambda: _rule_openaction_malicious_url(
                javascript_analysis, threat_intelligence
            ),
            lambda: _rule_embedded_exe_malware_hash(
                embedded_analysis, threat_intelligence
            ),
            lambda: _rule_obfuscated_js_malicious_url(
                javascript_analysis, threat_intelligence
            ),
            lambda: _rule_high_entropy_stream_malware_hash(
                stream_analysis, embedded_analysis, threat_intelligence
            ),
            lambda: _rule_newly_registered_domain_javascript(
                javascript_analysis, threat_intelligence
            ),
            lambda: _rule_typosquat_domain_openaction(
                javascript_analysis, iocs
            ),
            lambda: _rule_encrypted_pdf_embedded_files(
                metadata, embedded_analysis
            ),
            lambda: _rule_embedded_zip_malware_hash(
                embedded_analysis, threat_intelligence
            ),
            lambda: _rule_multiple_malicious_urls(threat_intelligence),
            lambda: _rule_malicious_ip_and_url(threat_intelligence),
        ]

        findings: List[Dict[str, Any]] = []

        for rule_call in rule_calls:
            try:
                result = rule_call()
            except Exception as e:
                log.error(f"Correlation rule failed: {e}")
                continue

            if result:
                findings.append(result)

        findings.sort(
            key=lambda f: SEVERITY_RANK.get(f["Severity"], len(_SEVERITY_ORDER))
        )

        try:
            overall_reputation = _build_overall_ioc_reputation(threat_intelligence)
        except Exception as e:
            log.error(f"Failed to build Overall IOC Reputation: {e}")
            overall_reputation = {
                "Total IOCs Checked": 0, "Malicious": 0, "Suspicious": 0,
                "Clean": 0, "Unknown": 0, "Highest Risk Score": 0,
                "Average Risk Score": 0, "Overall Verdict": "unknown",
                "Confidence": "None",
            }

        try:
            correlation_score = _calculate_correlation_score(findings)
        except Exception as e:
            log.error(f"Failed to calculate Correlation Score: {e}")
            correlation_score = 0

        return {
            "Overall IOC Reputation": overall_reputation,
            "Correlated Findings": findings,
            "Correlation Score": correlation_score,
        }


# ==========================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# ==========================================

def correlate_threats(
    metadata: Optional[Dict[str, Any]] = None,
    embedded_analysis: Optional[Dict[str, Any]] = None,
    javascript_analysis: Optional[Dict[str, Any]] = None,
    stream_analysis: Optional[Dict[str, Any]] = None,
    acroform_analysis: Optional[Dict[str, Any]] = None,
    compression_analysis: Optional[Dict[str, Any]] = None,
    iocs: Optional[Dict[str, Any]] = None,
    threat_intelligence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Module-level convenience wrapper around ThreatCorrelationEngine().correlate()."""

    return ThreatCorrelationEngine().correlate(
        metadata=metadata,
        embedded_analysis=embedded_analysis,
        javascript_analysis=javascript_analysis,
        stream_analysis=stream_analysis,
        acroform_analysis=acroform_analysis,
        compression_analysis=compression_analysis,
        iocs=iocs,
        threat_intelligence=threat_intelligence,
    )