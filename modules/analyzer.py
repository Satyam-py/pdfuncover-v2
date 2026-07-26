# modules/analyzer.py
"""
Threat-scoring engine for PDFUncover.

analyze_results() takes the raw metadata + embedded-object results and
turns them into a scored, human/machine-readable verdict (Threat Level,
Risk Score, Suspicious Findings, MITRE ATT&CK mapping, plus a richer
per-category "Evidence Report"). Report rendering is handled exclusively
by the Professional Report Engine (modules/report/).

Nothing in this module performs new detection — it only interprets and
scores results that modules/embedded_extraction.py (and its parsers)
and modules/metadata.py already produced.

SCORING MODEL
-------------
Risk Score and Threat Level are now derived from the Evidence Report
(modules/parsers/evidence.py + correlate_evidence() below) instead of a
flat per-category point sum. Rationale:

  * Independent findings are weighted by severity x confidence, then
    passed through a diminishing-returns curve (_diminishing_returns).
    A pile of unrelated Low/Medium-confidence findings (a URL here, an
    encrypted flag there, a missing /Author) asymptotically approaches
    the top of the range but cannot casually cross into it — matching
    how an analyst discounts many-weak-signals versus one strong one.
  * A small set of findings that are extremely common in benign,
    everyday PDFs — high-entropy streams and non-standard compression
    filters on their own, and encryption on its own — contribute zero
    *independent* score (see INDEPENDENT_WEIGHT_OVERRIDE). They still
    fully participate in correlation (e.g. entropy + compression
    together become "Possible Obfuscated Payload"), so real signal is
    preserved; it's the lone, low-context version of these findings
    that stops inflating the score.
  * Correlated / compound evidence (correlate_evidence()) represents
    genuine cross-signal corroboration — not just another weak data
    point — so it is added on top of the dampened base score rather
    than folded into the same diminishing-returns pool.
  * A CRITICAL verdict additionally requires at least one Critical-
    severity evidence item to actually be present (VT detection,
    executable payload, shellcode pattern, JBIG2/CVE-2010-0188, or a
    correlated compound finding). A numeric score alone — e.g. from
    stacking many High/Medium findings — is capped at HIGH without
    that corroboration. See _determine_threat_level().

The legacy per-category _score_* functions below are unchanged and
still populate the per-category analysis dicts, Suspicious Findings,
and MITRE ATT&CK lists exactly as before (so report content/format and
CLI output stay stable). Their point totals are kept only as a
fallback (`legacy_score`) used solely if the Evidence Report cannot be
built for some reason; they no longer drive Risk Score directly.
"""

import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from modules.parsers.evidence import (
    make_evidence,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
)

# A single Evidence object, exactly as produced by make_evidence() /
# build_evidence() in modules/parsers/evidence.py. This is a naming
# convenience only — the schema itself lives in the parsers layer and
# is not redefined or altered here.
EvidenceItem = Dict[str, Any]


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/analyzer.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# SCORING WEIGHTS
# ==========================================

# Legacy per-category point values. These still drive the informational
# per-category dicts (Header Analysis, JavaScript Analysis, ...) and are
# summed into `legacy_score`, which is used ONLY as a fallback if the
# Evidence Report fails to build (see analyze_results). The real Risk
# Score is computed by _calculate_risk_score() from the Evidence Report,
# using the weight tables below instead.
SCORES = {
    "js_detected":          20,
    "openaction":           15,
    "js_obfuscation":       20,
    "js_decoded_preview":   10,  # JS content was extractable = active script
    "url_found":             5,  # per URL, capped at 20
    "ip_found":              8,  # per IP, capped at 20
    "embedded_file":        25,
    "executable_payload":   40,
    "shellcode_pattern":    35,
    "high_entropy_stream":  15,  # per stream, capped at 30
    "compressed_objects":   10,
    "encrypted_pdf":        15,
    "jbig2_detected":       25,  # CVE-2010-0188 vector
    "acroform_detected":    10,
    "aa_trigger":           15,
    "xfa_form":             20,
    "invalid_header":       20,
    "suspicious_filename":  30,
    "zero_pages":           25,
    "suspicious_title":      5,
    "vt_malicious":         50,
}

# MITRE ATT&CK mappings for each finding type
MITRE_MAP = {
    "js_detected":          "T1059.007 — JavaScript execution",
    "openaction":           "T1204.002 — Malicious file auto-execution",
    "js_obfuscation":       "T1027 — Obfuscated files or information",
    "high_entropy_stream":  "T1027.002 — Software packing",
    "embedded_file":        "T1027 — Embedded payload",
    "executable_payload":   "T1204.002 — User execution: malicious file",
    "shellcode_pattern":    "T1055 — Process injection",
    "url_found":            "T1071.001 — Web protocol C2",
    "ip_found":             "T1071.001 — Web protocol C2",
    "acroform_detected":    "T1114 — Email/form data collection",
    "aa_trigger":           "T1204 — User execution trigger",
    "xfa_form":             "T1566.001 — Spearphishing attachment",
    "encrypted_pdf":        "T1027 — Encrypted/encoded file",
    "jbig2_detected":       "T1203 — Exploitation for client execution",
    "invalid_header":       "T1036 — Masquerading",
}

# ------------------------------------------------------------
# Evidence-weighted scoring model
# ------------------------------------------------------------
# Risk Score is computed from Evidence objects (severity + confidence),
# not from counting independent findings. See _calculate_risk_score().

# Base weight per severity tier. Deliberately convex (Critical is worth
# much more than 4x Low) so that reaching the top of the range requires
# genuinely severe findings, not just a lot of minor ones.
SEVERITY_WEIGHT: Dict[str, float] = {
    SEVERITY_CRITICAL: 40.0,
    SEVERITY_HIGH:      22.0,
    SEVERITY_MEDIUM:    10.0,
    SEVERITY_LOW:         3.0,
    SEVERITY_INFO:        0.0,
}

# Confidence discounts a finding's weight — a Low-confidence Critical
# finding should not score like a High-confidence one.
CONFIDENCE_MULTIPLIER: Dict[str, float] = {
    CONFIDENCE_HIGH:    1.0,
    CONFIDENCE_MEDIUM:  0.65,
    CONFIDENCE_LOW:     0.35,
}

# Findings that are common in ordinary, benign PDFs and therefore carry
# ~no signal on their own — only in combination with something else.
# They still fully participate in correlate_evidence() (matched by id
# there against the raw evidence list, independent of scoring weight);
# this override only zeroes their *independent* contribution to the
# Risk Score, per "images/compression/entropy alone must not raise
# risk".
INDEPENDENT_WEIGHT_OVERRIDE: Dict[str, float] = {
    # Entropy alone is a coin flip — plenty of legitimate compressed
    # streams (images, embedded fonts) read as high-entropy. It only
    # becomes meaningful stacked with unusual compression, which is
    # exactly what correlation.obfuscated_payload captures.
    "stream.high_entropy":              0.0,
    # Uncommon filters are frequently just images/fonts encoded a
    # slightly unusual way. Real signal comes from correlation with
    # entropy, not the filter name alone.
    "compression.nonstandard_filter":   0.0,
    # Password-protected/encrypted PDFs are routine in business
    # contexts (HR, finance, legal). Encryption is only worth scoring
    # when paired with something that actually indicates evasion.
    "encryption.enabled":               0.0,
}

# Correlated (compound) evidence is added on top of the dampened base
# score rather than mixed into the same diminishing-returns pool, since
# it represents genuine cross-signal corroboration rather than another
# independent weak data point. This multiplier controls how much of
# each correlated finding's weight actually lands on the score.
CORRELATION_BOOST_MULTIPLIER = 0.5

# Diminishing-returns "half life" for the independent-evidence pool:
# roughly the amount of weighted independent evidence needed to reach
# ~63 points before correlation boosts are added. Tuned so that a
# single strong (Critical/High, High-confidence) finding lands solidly
# in HIGH territory, while several unrelated Low/Medium findings top
# out well short of that.
INDEPENDENT_SCORE_HALF_LIFE = 42.0

# Evidence severities, ordered from most to least severe. Used both to
# sort the Evidence Report and to build its per-severity summary counts,
# so the two always agree on ordering by construction.
SEVERITY_LEVELS: List[str] = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

SEVERITY_RANK: Dict[str, int] = {
    severity: rank for rank, severity in enumerate(SEVERITY_LEVELS)
}

# JS keywords considered obfuscation indicators when seen in the document.
# app.alert and base64 are intentionally excluded — see notes below.
OBFUSCATION_PATTERNS = [
    "eval",
    "unescape",
    "fromCharCode",
    "atob",
    "app.launchURL",
    "this.exportDataObject",
    "submitForm",
    "Collab.collectEmailInfo",
    "util.printf",
    "getAnnots"
    # app.alert removed — it's a dialog, not obfuscation
    # base64 removed — string match too broad, causes false positives
]

# JS API calls with a documented history of exploit abuse.
EXPLOIT_INDICATORS = [
    "app.launchURL",
    "this.exportDataObject",
    "Collab.collectEmailInfo",
    "util.printf"
]

# Dangerous file extensions for embedded-file scoring.
DANGEROUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".scr",
    ".hta", ".jar", ".sh"
]


# ==========================================
# HELPERS
# ==========================================

def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse nested dicts without KeyError.
    safe_get(results, 'JavaScript', 'Suspicious Keywords', default=[])
    """

    current = d

    for key in keys:

        if not isinstance(current, dict):
            return default

        current = current.get(key, default)

        if current is default:
            return default

    return current


def cap(value: float, maximum: float) -> float:
    """Return value capped at maximum."""
    return min(value, maximum)


# ==========================================
# EVIDENCE CORRELATION
# ==========================================
#
# Individual detectors (in embedded_extraction.py) already emit
# standardized Evidence objects for each thing they find in isolation.
# A real investigation doesn't stop there — an analyst reads several
# weak/individual signals TOGETHER and draws a stronger conclusion.
#
# This function performs exactly that: it looks for known evidence
# COMBINATIONS (by id) that already exist in the evidence list, and
# synthesizes a higher-level "Correlated Behavior" finding from them.
# It does not introduce any new raw detection — every correlation
# below is built entirely from evidence the extraction layer already
# produced.
#

def _has(
    evidence_list: List[EvidenceItem],
    *,
    id_prefix: Optional[str] = None,
    id_exact: Optional[str] = None,
) -> bool:
    """True if any evidence item matches the given id/id-prefix."""

    for e in evidence_list:
        if id_exact and e["id"] == id_exact:
            return True
        if id_prefix and e["id"].startswith(id_prefix):
            return True

    return False


def correlate_evidence(
    evidence_list: List[EvidenceItem],
    embedded_results: Dict[str, Any],
    metadata: Dict[str, Any],
) -> List[EvidenceItem]:
    """
    Cross-reference already-produced Evidence objects and synthesize
    compound findings that reflect how the individual pieces combine
    into an actual attack behavior.
    """

    correlated = []

    # ------------------------------------------------------------
    # JavaScript + OpenAction -> auto-execution
    # ------------------------------------------------------------

    if (
        _has(evidence_list, id_exact="js.detected")
        and _has(evidence_list, id_exact="js.openaction")
    ):
        correlated.append(make_evidence(
            id="correlation.js_auto_exec",
            category="Correlated Behavior",
            title="JavaScript Auto-Execution",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence="Document contains both a /JavaScript object and an "
                     "/OpenAction trigger — the script is wired to run the "
                     "moment the file is opened.",
            impact="Executes attacker-controlled JavaScript automatically "
                   "when the PDF opens, without any user interaction.",
            recommendation="Extract and analyze the JavaScript (statically "
                            "and in a sandboxed reader) before this file is "
                            "opened by anyone.",
            mitre=["T1204.002", "T1059.007"],
            tags=["correlation", "javascript", "auto-exec"],
        ))

    # ------------------------------------------------------------
    # Embedded executable + launch-capable JS -> possible dropper
    # ------------------------------------------------------------

    if (
        _has(evidence_list, id_prefix="embedded.executable")
        and _has(evidence_list, id_prefix="js.exploit_api.app_launchurl")
    ):
        correlated.append(make_evidence(
            id="correlation.dropper",
            category="Correlated Behavior",
            title="Possible Malware Dropper",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence="An embedded executable is present alongside a "
                     "JavaScript app.launchURL() call capable of invoking "
                     "external content.",
            impact="The PDF may function as a dropper — using a scripted "
                   "launch action to execute the embedded payload on the "
                   "victim's machine.",
            recommendation="Treat the embedded file as live malware. "
                            "Detonate only in an isolated sandbox and submit "
                            "its hash to VirusTotal / internal AV.",
            mitre=["T1204.002", "T1027"],
            tags=["correlation", "dropper", "executable"],
        ))

    # ------------------------------------------------------------
    # High entropy stream + compressed objects -> obfuscated payload
    # ------------------------------------------------------------

    if (
        _has(evidence_list, id_prefix="stream.high_entropy")
        and safe_get(embedded_results, "Compression", "Compressed Objects Found")
    ):
        correlated.append(make_evidence(
            id="correlation.obfuscated_payload",
            category="Correlated Behavior",
            title="Possible Obfuscated Payload",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_MEDIUM,
            evidence="One or more streams show entropy above 7.2 while also "
                     "being marked as compressed — higher than standard "
                     "compression alone typically produces.",
            impact="May indicate a packed, encrypted, or otherwise "
                   "obfuscated payload layered on top of standard "
                   "compression to evade static detection.",
            recommendation="Manually decompress and inspect the flagged "
                            "stream(s) for embedded shellcode, executables, "
                            "or secondary payloads.",
            mitre=["T1027.002", "T1027"],
            tags=["correlation", "entropy", "obfuscation"],
        ))

    # ------------------------------------------------------------
    # AcroForm + /AA trigger -> silent data exfiltration
    # ------------------------------------------------------------

    if (
        _has(evidence_list, id_exact="acroform.detected")
        and _has(evidence_list, id_exact="acroform.aa_trigger")
    ):
        correlated.append(make_evidence(
            id="correlation.silent_exfil_form",
            category="Correlated Behavior",
            title="Auto-Triggered Form Submission Risk",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_MEDIUM,
            evidence="Document contains both an /AcroForm and an /AA "
                     "additional-action trigger, meaning a form-related "
                     "action can fire without user interaction.",
            impact="Field data could be submitted (submitForm) to a remote "
                   "server automatically, without the victim taking any "
                   "visible action.",
            recommendation="Identify the /AA target and confirm whether it "
                            "invokes submitForm(); trace the submission URL.",
            mitre=["T1114", "T1204"],
            tags=["correlation", "form", "exfiltration"],
        ))

    # ------------------------------------------------------------
    # VirusTotal detection + any local evidence -> corroboration
    # ------------------------------------------------------------

    vt = metadata.get("VirusTotal", {}) or {}

    if vt.get("Found") and vt.get("Malicious", 0) > 0 and evidence_list:
        correlated.append(make_evidence(
            id="correlation.vt_corroboration",
            category="Correlated Behavior",
            title="Local Findings Corroborated by VirusTotal",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence=f"{vt.get('Malicious')} / {vt.get('Total', '?')} AV "
                     f"engines flag this file, consistent with the "
                     f"{len(evidence_list)} local finding(s) identified "
                     f"during static analysis.",
            impact="Independent multi-engine AV detection combined with "
                   "local static findings significantly raises confidence "
                   "that this file is malicious rather than a false positive.",
            recommendation="Prioritize this file for immediate containment "
                            "and IR escalation.",
            tags=["correlation", "virustotal"],
        ))

    return correlated


def _build_virustotal_evidence(metadata: Dict[str, Any]) -> List[EvidenceItem]:
    """
    Re-represent a VirusTotal detection (if any) as an analyzer-level
    Evidence object. metadata.py / virustotal.py are untouched — this
    only reads the "VirusTotal" field they already populate.

    Returns a 0- or 1-item list so callers can .extend() it directly.
    """

    vt = metadata.get("VirusTotal", {}) or {}

    if not (vt.get("Found") and vt.get("Malicious", 0) > 0):
        return []

    return [make_evidence(
        id="vt.malicious",
        category="Reputation",
        title="VirusTotal Detection",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        evidence=f"{vt.get('Malicious')} / {vt.get('Total', '?')} "
                 f"engines flagged this file as malicious.",
        impact="Multi-engine AV consensus indicates this file matches "
               "known malware signatures.",
        recommendation="Prioritize for containment; do not rely solely "
                        "on local static analysis.",
        tags=["reputation", "virustotal"],
    )]


def _metadata_anomaly_id(flag: str) -> str:
    """Slugify a metadata.py "Suspicious Flags" string into an evidence id."""

    slug = re.sub(r"[^a-z0-9]+", "_", flag.lower()).strip("_")[:40]
    return f"metadata.anomaly.{slug}"


def _build_metadata_anomaly_evidence(metadata: Dict[str, Any]) -> List[EvidenceItem]:
    """
    Re-represent each metadata.py "Suspicious Flags" entry (missing
    author/creator, date mismatches, etc.) as an analyzer-level
    Evidence object, one per flag.
    """

    return [
        make_evidence(
            id=_metadata_anomaly_id(flag),
            category="Metadata Anomaly",
            title="Suspicious Metadata",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_MEDIUM,
            evidence=flag,
            impact="Anomalies such as missing author/creator fields or date "
                   "mismatches are common in crafted or spoofed documents, "
                   "though also occur in legitimately stripped files.",
            recommendation="Compare against known-good samples from the "
                            "same purported source/template.",
            mitre=["T1036"],
            tags=["metadata"],
        )
        for flag in (metadata.get("Suspicious Flags", []) or [])
    ]


def _count_by_severity(evidence: List[EvidenceItem], severity: str) -> int:
    """Number of evidence items at a given severity."""
    return sum(1 for e in evidence if e.get("severity") == severity)


def build_evidence_report(
    metadata: Dict[str, Any],
    embedded_results: Dict[str, Any],
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Assemble the full evidence-based investigation view:
      - primitive Evidence objects from the extraction layer
      - analyzer-level Evidence (VirusTotal, metadata anomalies)
      - correlated / compound Evidence built from combinations of the above

    This is purely additive: it is attached to analysis["Evidence Report"]
    and does not change Risk Score, Threat Level, Suspicious Findings, or
    MITRE ATT&CK — those remain computed exactly as before for backward
    compatibility with the existing CLI and reports.
    """

    # ---- Base evidence already produced by the extraction layer ----
    evidence: List[EvidenceItem] = list(
        safe_get(embedded_results, "Evidence", default=[]) or []
    )

    # ---- Analyzer-level evidence (same content/order as before, now
    #      built by dedicated helpers instead of inline) ----
    evidence.extend(_build_virustotal_evidence(metadata))
    evidence.extend(_build_metadata_anomaly_evidence(metadata))

    # ---- Correlate across everything gathered so far ----
    correlated = correlate_evidence(evidence, embedded_results, metadata)
    evidence.extend(correlated)

    evidence.sort(key=lambda e: SEVERITY_RANK.get(e.get("severity"), len(SEVERITY_LEVELS)))

    summary: Dict[str, Any] = {"Total Evidence": len(evidence)}
    for severity in SEVERITY_LEVELS:
        summary[severity] = _count_by_severity(evidence, severity)
    summary["Correlated Findings"] = len(correlated)

    return {
        "evidence": evidence,
        "correlations": correlated,
        "summary": summary,
    }


# ==========================================
# PER-CATEGORY SCORING SECTIONS
# ==========================================
#
# Each _score_* function below owns exactly one section of the original
# analyze_results() body. They mutate `suspicious_findings` and
# `mitre_techniques` in place (so call order below == original append
# order) and return (category_analysis_dict, score_delta). This is a
# pure reorganization for readability — the scoring math, finding
# strings, and MITRE mappings are untouched.
#

def _score_header(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """Header validation: score an invalid %PDF- magic-byte header."""

    header_analysis = {"Invalid Header": False}
    score = 0

    if not safe_get(
        embedded_results, "Header Validation", "Valid PDF Header",
        default=True
    ):
        header_analysis["Invalid Header"] = True
        score += SCORES["invalid_header"]
        suspicious_findings.append("Invalid PDF header — possible spoofed file")
        mitre_techniques.append(MITRE_MAP["invalid_header"])

    return header_analysis, score


def _score_javascript(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """JavaScript presence, OpenAction triggers, obfuscation, decoded preview."""

    js_analysis = {
        "Obfuscation Detected":  False,
        "Obfuscation Patterns":  [],
        "Exploit Indicators":    [],
        "Decoded JS Preview":    ""
    }
    score = 0

    js_keywords = safe_get(
        embedded_results, "JavaScript", "Suspicious Keywords", default=[]
    )

    for keyword in js_keywords:

        if keyword in OBFUSCATION_PATTERNS:
            js_analysis["Obfuscation Detected"] = True
            js_analysis["Obfuscation Patterns"].append(keyword)

        if keyword in EXPLOIT_INDICATORS:
            js_analysis["Exploit Indicators"].append(keyword)

    # JS detected
    if safe_get(embedded_results, "JavaScript", "JavaScript Detected"):
        score += SCORES["js_detected"]
        suspicious_findings.append("Embedded JavaScript detected")
        mitre_techniques.append(MITRE_MAP["js_detected"])

    # OpenAction
    if safe_get(embedded_results, "JavaScript", "OpenAction Found"):
        score += SCORES["openaction"]
        suspicious_findings.append("OpenAction auto-execution trigger found")
        mitre_techniques.append(MITRE_MAP["openaction"])

    # Obfuscation
    if js_analysis["Obfuscation Detected"]:
        score += SCORES["js_obfuscation"]
        suspicious_findings.append(
            f"JavaScript obfuscation detected: "
            f"{', '.join(js_analysis['Obfuscation Patterns'])}"
        )
        mitre_techniques.append(MITRE_MAP["js_obfuscation"])

    # Decoded JS preview available = active script content
    preview = safe_get(
        embedded_results, "JavaScript", "Decoded JS Preview", default=""
    )

    if preview:
        js_analysis["Decoded JS Preview"] = preview
        score += SCORES["js_decoded_preview"]

    return js_analysis, score


def _score_iocs(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """URLs and IPs found inside the document (per-item score, capped)."""

    ioc_analysis = {
        "URLs Found":    0,
        "Domains Found": 0,
        "IPs Found":     0,
        "URL List":      [],
        "IP List":       []
    }
    score = 0

    urls    = safe_get(embedded_results, "IOCs", "URLs",    default=[])
    domains = safe_get(embedded_results, "IOCs", "Domains", default=[])
    ips     = safe_get(embedded_results, "IOCs", "IPs",     default=[])

    ioc_analysis["URLs Found"]    = len(urls)
    ioc_analysis["Domains Found"] = len(domains)
    ioc_analysis["IPs Found"]     = len(ips)
    ioc_analysis["URL List"]      = urls
    ioc_analysis["IP List"]       = ips

    if urls:
        score += cap(len(urls) * SCORES["url_found"], 20)
        suspicious_findings.append(
            f"{len(urls)} URL(s) found inside PDF"
        )
        mitre_techniques.append(MITRE_MAP["url_found"])

    if ips:
        score += cap(len(ips) * SCORES["ip_found"], 20)
        suspicious_findings.append(
            f"{len(ips)} IP address(es) found inside PDF"
        )
        mitre_techniques.append(MITRE_MAP["ip_found"])

    return ioc_analysis, score


def _score_embedded_files(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """Extracted embedded files, executable payloads, dangerous filenames."""

    embedded_analysis = {
        "Embedded Files":       [],
        "Executables Detected": False,
        "Executable Indicators": [],
        "Suspicious Files":     []
    }
    score = 0

    extracted_files = safe_get(
        embedded_results, "Embedded Files", "Extracted Files", default=[]
    )

    suspicious_files = safe_get(
        embedded_results, "Embedded Files", "Suspicious Files", default=[]
    )

    for file_path in extracted_files:

        embedded_analysis["Embedded Files"].append(file_path)
        lower_path = file_path.lower()

        for ext in DANGEROUS_EXTENSIONS:

            if lower_path.endswith(ext):
                embedded_analysis["Executables Detected"] = True
                embedded_analysis["Executable Indicators"].append(ext)

    embedded_analysis["Suspicious Files"] = suspicious_files

    if extracted_files:
        score += SCORES["embedded_file"]
        suspicious_findings.append(
            f"{len(extracted_files)} embedded file(s) detected"
        )
        mitre_techniques.append(MITRE_MAP["embedded_file"])

    if embedded_analysis["Executables Detected"]:
        score += SCORES["executable_payload"]
        suspicious_findings.append(
            f"Executable payload detected: "
            f"{', '.join(set(embedded_analysis['Executable Indicators']))}"
        )
        mitre_techniques.append(MITRE_MAP["executable_payload"])

    if suspicious_files:
        score += SCORES["suspicious_filename"]
        for sf in suspicious_files:
            suspicious_findings.append(f"Dangerous embedded file: {sf}")

    return embedded_analysis, score


def _score_streams(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """High-entropy streams and shellcode byte patterns."""

    stream_analysis = {
        "High Entropy Streams":    [],
        "Shellcode Findings":      [],
        "Decompressed Content":    False
    }
    score = 0

    high_entropy = safe_get(
        embedded_results, "Streams", "High Entropy Streams", default=[]
    )

    shellcode_findings = safe_get(
        embedded_results, "Streams", "Decompressed Findings", default=[]
    )

    stream_analysis["High Entropy Streams"] = high_entropy
    stream_analysis["Shellcode Findings"]   = shellcode_findings

    if high_entropy:
        score += cap(len(high_entropy) * SCORES["high_entropy_stream"], 30)
        suspicious_findings.append(
            f"{len(high_entropy)} high-entropy stream(s) — "
            "possible encrypted/packed payload"
        )
        mitre_techniques.append(MITRE_MAP["high_entropy_stream"])

    if shellcode_findings:
        score += SCORES["shellcode_pattern"]
        for finding in shellcode_findings:
            suspicious_findings.append(f"Shellcode pattern: {finding}")
        mitre_techniques.append(MITRE_MAP["shellcode_pattern"])

    return stream_analysis, score


def _score_compression(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """Non-standard compression filters, JBIG2 (CVE-2010-0188), encryption."""

    compression_analysis = {
        "Compressed Objects": False,
        "Filters":            [],
        "JBIG2 Detected":     False
    }
    score = 0

    if safe_get(
        embedded_results, "Compression", "Compressed Objects Found"
    ):
        compression_analysis["Compressed Objects"] = True
        compression_analysis["Filters"] = safe_get(
            embedded_results, "Compression", "Filters", default=[]
        )
        # FlateDecode is standard in virtually all modern PDFs
        # Only score if combined with other suspicious indicators
        filters = compression_analysis["Filters"]
        non_standard = [f for f in filters if f not in ("FlateDecode", "DCTDecode", "CCITTFaxDecode")]
        if non_standard:
            score += SCORES["compressed_objects"]
            suspicious_findings.append(
                f"Non-standard compression filters: {', '.join(non_standard)}"
            )

    if safe_get(embedded_results, "Compression", "JBIG2 Warning"):
        compression_analysis["JBIG2 Detected"] = True
        score += SCORES["jbig2_detected"]
        suspicious_findings.append(
            "JBIG2Decode detected — CVE-2010-0188 exploit vector"
        )
        mitre_techniques.append(MITRE_MAP["jbig2_detected"])

    if safe_get(embedded_results, "Encryption", "Encrypted"):
        score += SCORES["encrypted_pdf"]
        suspicious_findings.append("Encrypted PDF")
        mitre_techniques.append(MITRE_MAP["encrypted_pdf"])

    return compression_analysis, score


def _score_forms(
    embedded_results: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """AcroForm / /AA additional-action / XFA form detection."""

    form_analysis = {
        "AcroForm Detected":        False,
        "Additional Actions Found": False,
        "XFA Form Detected":        False
    }
    score = 0

    if safe_get(embedded_results, "AcroForm", "AcroForm Detected"):
        form_analysis["AcroForm Detected"] = True
        score += SCORES["acroform_detected"]
        suspicious_findings.append(
            "AcroForm detected — possible data exfiltration via submitForm"
        )
        mitre_techniques.append(MITRE_MAP["acroform_detected"])

    if safe_get(embedded_results, "AcroForm", "Additional Actions Found"):
        form_analysis["Additional Actions Found"] = True
        score += SCORES["aa_trigger"]
        suspicious_findings.append(
            "/AA trigger found — action fires on page open/close"
        )
        mitre_techniques.append(MITRE_MAP["aa_trigger"])

    if safe_get(embedded_results, "AcroForm", "XFA Form Detected"):
        form_analysis["XFA Form Detected"] = True
        score += SCORES["xfa_form"]
        suspicious_findings.append(
            "XFA form detected — used in exploit delivery"
        )
        mitre_techniques.append(MITRE_MAP["xfa_form"])

    return form_analysis, score


def _score_metadata_anomalies(
    metadata: Dict[str, Any],
    suspicious_findings: List[str],
    mitre_techniques: List[str],
) -> Tuple[Dict[str, Any], int]:
    """Suspicious title/author/creator/producer/date flags from metadata.py."""

    meta_analysis = {
        "Suspicious Title":    False,
        "Missing Author":      False,
        "Missing Creator":     False,
        "Date Mismatch":       False,
        "Suspicious Producer": False
    }
    score = 0

    meta_flags = metadata.get("Suspicious Flags", [])

    for flag in meta_flags:

        flag_lower = flag.lower()

        if "title" in flag_lower:
            meta_analysis["Suspicious Title"] = True
            score += SCORES["suspicious_title"]
            suspicious_findings.append(flag)
            mitre_techniques.append(MITRE_MAP.get("suspicious_title", ""))

        if "author" in flag_lower:
            meta_analysis["Missing Author"] = True
            suspicious_findings.append(flag)

        if "creator" in flag_lower:
            meta_analysis["Missing Creator"] = True
            suspicious_findings.append(flag)

        if "modified" in flag_lower or "differ" in flag_lower:
            meta_analysis["Date Mismatch"] = True
            suspicious_findings.append(flag)

        if "producer" in flag_lower:
            meta_analysis["Suspicious Producer"] = True
            suspicious_findings.append(flag)

        if "0 pages" in flag_lower:
            score += SCORES["zero_pages"]
            suspicious_findings.append(flag)

    return meta_analysis, score


def _score_virustotal(
    metadata: Dict[str, Any],
    suspicious_findings: List[str],
) -> int:
    """VirusTotal multi-engine detection score."""

    score = 0
    vt_data = metadata.get("VirusTotal", {})

    if vt_data.get("Found"):

        malicious = vt_data.get("Malicious", 0)

        if malicious > 0:
            score += SCORES["vt_malicious"]
            suspicious_findings.append(
                f"VirusTotal: detected by {malicious} engines"
            )

    return score


def _threat_level_for_score(score: int) -> str:
    """Map a 0-100 risk score to a threat-level bucket (numeric part only —
    see _determine_threat_level() for the corroboration gate applied on
    top of this)."""

    if score <= 15:
        return "CLEAN"
    if score <= 35:
        return "LOW"
    if score <= 55:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


# ==========================================
# EVIDENCE-WEIGHTED RISK SCORE
# ==========================================
#
# Replaces flat "sum of independent per-category points" scoring. See
# the module docstring for the full rationale; in short:
#   1. Every Evidence object is weighted by severity x confidence.
#   2. Findings that are common in benign PDFs on their own (entropy,
#      non-standard compression, encryption) are zeroed out here —
#      they only score once correlate_evidence() turns them into a
#      compound finding.
#   3. Independent findings are summed and passed through a
#      diminishing-returns curve, so many weak/unrelated findings
#      cannot simply add up to a severe score.
#   4. Correlated findings are added on top, uncapped by that curve,
#      since correlation reflects real corroboration rather than more
#      of the same weak signal.
#

def _evidence_weight(item: EvidenceItem) -> float:
    """Severity x confidence weight for one Evidence object, with the
    "common in benign PDFs alone" override applied."""

    item_id = item.get("id", "") or ""

    for prefix, override in INDEPENDENT_WEIGHT_OVERRIDE.items():
        if item_id.startswith(prefix):
            return override

    severity_weight = SEVERITY_WEIGHT.get(item.get("severity"), 0.0)
    confidence_mult  = CONFIDENCE_MULTIPLIER.get(item.get("confidence"), 0.5)

    return severity_weight * confidence_mult


def _diminishing_returns(raw: float, half_life: float = INDEPENDENT_SCORE_HALF_LIFE) -> float:
    """
    Map an unbounded weighted-evidence sum onto a bounded 0-100 curve
    with diminishing returns, so each additional independent finding
    contributes progressively less. Approaches, but never reaches, 100.
    """

    if raw <= 0:
        return 0.0

    return 100.0 * (1.0 - math.exp(-raw / half_life))


def _calculate_risk_score(
    evidence_list: List[EvidenceItem],
    correlated: List[EvidenceItem],
) -> int:
    """
    Compute the 0-100 Risk Score from the Evidence Report.

    Independent (non-correlated) evidence is weighted, summed, and
    dampened via diminishing returns. Correlated/compound evidence is
    added on top at CORRELATION_BOOST_MULTIPLIER, uncapped by the
    dampening — a synthesized compound finding (e.g. "JavaScript
    Auto-Execution" from JS + OpenAction together) is stronger evidence
    than either finding alone, and should move the needle accordingly.
    """

    correlated_ids = {e.get("id") for e in correlated}
    independent = [e for e in evidence_list if e.get("id") not in correlated_ids]

    independent_raw = sum(_evidence_weight(e) for e in independent)
    base_score = _diminishing_returns(independent_raw)

    correlation_raw = sum(_evidence_weight(e) for e in correlated)
    correlation_boost = correlation_raw * CORRELATION_BOOST_MULTIPLIER

    score = base_score + correlation_boost

    return int(round(min(100.0, max(0.0, score))))


def _determine_threat_level(score: int, evidence_list: List[EvidenceItem]) -> str:
    """
    Map the Risk Score to a Threat Level bucket, then gate CRITICAL
    behind actual corroborating evidence.

    A CRITICAL verdict requires at least one Critical-severity item to
    be present in the evidence list (VT detection, executable payload,
    shellcode pattern, JBIG2/CVE-2010-0188, or a correlated compound
    finding — Critical severity is reserved for exactly these in
    modules/parsers/evidence.py and correlate_evidence()). Without one,
    even a numerically high score — e.g. from stacking several
    High/Medium findings — is capped at HIGH. This directly implements
    "multiple weak findings should not automatically become Critical".
    """

    level = _threat_level_for_score(score)

    if level == "CRITICAL":
        has_critical_evidence = any(
            e.get("severity") == SEVERITY_CRITICAL for e in evidence_list
        )
        if not has_critical_evidence:
            level = "HIGH"

    return level


# ==========================================
# ANALYSIS ENGINE
# ==========================================

def analyze_results(
    metadata: Dict[str, Any],
    embedded_results: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run full threat analysis across metadata and embedded results.
    Returns structured analysis dict with score, threat level,
    MITRE mappings, and per-category findings.
    """

    analysis: Dict[str, Any] = {}
    suspicious_findings: List[str] = []
    mitre_techniques: List[str] = []
    legacy_score = 0

    # Each helper below owns exactly one section of the original
    # inline implementation, called in the original order so the
    # per-category analysis dicts, Suspicious Findings, and MITRE
    # ATT&CK lists are identical in content/order to before. Their
    # point totals are accumulated into `legacy_score`, which is used
    # ONLY as a fallback below if the Evidence Report can't be built —
    # the real Risk Score comes from the evidence-weighted engine.

    header_analysis, delta = _score_header(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["Header Analysis"] = header_analysis
    legacy_score += delta

    js_analysis, delta = _score_javascript(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["JavaScript Analysis"] = js_analysis
    legacy_score += delta

    ioc_analysis, delta = _score_iocs(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["IOC Analysis"] = ioc_analysis
    legacy_score += delta

    embedded_analysis, delta = _score_embedded_files(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["Embedded File Analysis"] = embedded_analysis
    legacy_score += delta

    stream_analysis, delta = _score_streams(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["Stream Analysis"] = stream_analysis
    legacy_score += delta

    compression_analysis, delta = _score_compression(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["Compression Analysis"] = compression_analysis
    legacy_score += delta

    form_analysis, delta = _score_forms(
        embedded_results, suspicious_findings, mitre_techniques
    )
    analysis["Form Analysis"] = form_analysis
    legacy_score += delta

    meta_analysis, delta = _score_metadata_anomalies(
        metadata, suspicious_findings, mitre_techniques
    )
    analysis["Metadata Analysis"] = meta_analysis
    legacy_score += delta

    legacy_score += _score_virustotal(metadata, suspicious_findings)
    legacy_score = min(legacy_score, 100)

    # Deduplicate MITRE techniques, preserving first-seen order
    mitre_techniques = list(dict.fromkeys(
        t for t in mitre_techniques if t
    ))

    # ==========================================
    # EVIDENCE REPORT
    # ==========================================
    # Built before the final score now, since it is the scoring
    # backbone rather than an afterthought. correlate_evidence() runs
    # inside build_evidence_report() and cross-references everything
    # gathered so far (parser evidence + VT + metadata anomalies).

    try:
        evidence_report = build_evidence_report(
            metadata, embedded_results, analysis
        )
    except Exception as e:
        log.error(f"Evidence report build failed: {e}")
        evidence_report = {"evidence": [], "correlations": [], "summary": {}}

    analysis["Evidence Report"] = evidence_report

    # ==========================================
    # RISK SCORE & THREAT LEVEL
    # ==========================================
    # Evidence-weighted, correlation-aware, and gated against a
    # CRITICAL verdict from weak findings alone. See
    # _calculate_risk_score() / _determine_threat_level() above.

    evidence_list = evidence_report.get("evidence", [])
    correlated    = evidence_report.get("correlations", [])

    if evidence_list:
        score = _calculate_risk_score(evidence_list, correlated)
    else:
        # Evidence model produced nothing (or failed to build) — fall
        # back to the legacy per-category sum so scoring never
        # silently collapses to 0 on an otherwise-flagged file.
        score = legacy_score

    threat_level = _determine_threat_level(score, evidence_list)

    # ==========================================
    # FINAL RESULTS
    # ==========================================

    analysis["Risk Score"]          = score
    analysis["Threat Level"]        = threat_level
    analysis["Suspicious Findings"] = suspicious_findings
    analysis["MITRE ATT&CK"]        = mitre_techniques

    return analysis