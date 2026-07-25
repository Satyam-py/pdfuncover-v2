# modules/parsers/evidence.py
#
# The Evidence model: severity/confidence constants, the make_evidence()
# builder, and build_evidence(), which converts the already-computed
# per-category result dicts into standardized Evidence objects.
#
# Moved verbatim from modules/embedded_extraction.py — no logic changed.
# This performs no new detection; it only re-represents findings that
# the parser modules already computed, using a standardized schema that
# analyzer.py can correlate and score.

import os
import re
import logging


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/embedded_extraction.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# EVIDENCE MODEL
# ==========================================

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Informational"

CONFIDENCE_HIGH = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW = "Low"

# Exploit-capable JS API calls — same set analyzer.py already treats
# as "exploit indicators" (not a new list, just reused here so the
# extraction layer can label these evidence items consistently).
EXPLOIT_API_KEYWORDS = {
    "app.launchURL",
    "this.exportDataObject",
    "Collab.collectEmailInfo",
    "util.printf",
}

STANDARD_COMPRESSION_FILTERS = ("FlateDecode", "DCTDecode", "CCITTFaxDecode")


def _slug(text):
    """Turn free text into a short, id-safe slug."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:40]


def make_evidence(
    id, category, title, severity, confidence,
    evidence, impact, recommendation,
    mitre=None, obj=None, tags=None
):
    """
    Build a single standardized Evidence object.

    {
        "id": "...",
        "category": "...",
        "title": "...",
        "severity": "Critical|High|Medium|Low|Informational",
        "confidence": "High|Medium|Low",
        "evidence": "... why this finding exists ...",
        "impact": "... what it could enable ...",
        "recommendation": "... what the analyst should do next ...",
        "mitre": [...],
        "object": "...",       # object number / stream index / file, if known
        "tags": [...]
    }
    """

    return {
        "id": id,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "mitre": mitre or [],
        "object": obj,
        "tags": tags or [],
    }


# ==========================================
# EVIDENCE BUILDER
# ==========================================

def build_evidence(
    header_data, stream_data, js_data, ioc_data,
    embedded_data, compression_data, encryption_data, acroform_data
):
    """
    Convert the raw per-detector results (already computed above) into
    a list of standardized Evidence objects. This performs no new
    detection — it only explains, for each existing finding, WHY it
    fired, WHAT it could enable, and WHAT the analyst should do next.
    """

    evidence = []

    # ---------------- Header ----------------

    if not header_data.get("Valid PDF Header"):
        evidence.append(make_evidence(
            id="header.invalid",
            category="Structural Anomaly",
            title="Invalid PDF Header",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            evidence=(header_data.get("Header Warning")
                      or "File does not start with the %PDF- magic bytes."),
            impact="A spoofed or corrupted header can be used to smuggle a file "
                   "past extension/type-based filters that expect a real PDF.",
            recommendation="Confirm the true file type with a hex/magic-byte "
                            "inspection before proceeding with PDF-specific tooling.",
            mitre=["T1036"],
            tags=["header", "masquerading"],
        ))

    # ---------------- JavaScript ----------------

    if js_data.get("JavaScript Detected"):
        preview = js_data.get("Decoded JS Preview")
        evidence.append(make_evidence(
            id="js.detected",
            category="JavaScript Execution",
            title="Embedded JavaScript",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            evidence=(f"Document contains a /JavaScript object. Decoded preview: "
                      f"\"{preview}\"" if preview else
                      "Document contains a /JavaScript object referenced by "
                      "the document catalog or an annotation."),
            impact="JavaScript execution capability increases attack surface, "
                   "even without a confirmed auto-execution trigger.",
            recommendation="Review the decoded JavaScript for obfuscation or "
                            "exploit API calls.",
            mitre=["T1059.007"],
            tags=["javascript"],
        ))

    if js_data.get("OpenAction Found"):
        evidence.append(make_evidence(
            id="js.openaction",
            category="Auto-Execution Trigger",
            title="OpenAction Trigger",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            evidence="An /OpenAction entry was found in the document catalog.",
            impact="Causes an associated action (frequently JavaScript) to run "
                   "automatically the moment the document is opened, without "
                   "any user interaction.",
            recommendation="Identify what /OpenAction points to and inspect it "
                            "directly (e.g. `pdf-parser --search OpenAction`).",
            mitre=["T1204.002"],
            tags=["javascript", "auto-exec"],
        ))

    obfuscation_keywords = [
        k for k in js_data.get("Suspicious Keywords", [])
        if k not in EXPLOIT_API_KEYWORDS
    ]

    if obfuscation_keywords:
        evidence.append(make_evidence(
            id="js.obfuscation",
            category="JavaScript Execution",
            title="JavaScript Obfuscation Indicators",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_MEDIUM,
            evidence=f"Suspicious API/keyword usage: {', '.join(obfuscation_keywords)}.",
            impact="These calls (eval, unescape, fromCharCode, submitForm, "
                   "getAnnots, app.alert) are commonly used to decode or hide "
                   "malicious script logic from static scanners.",
            recommendation="Manually decode the JavaScript payload and trace "
                            "each flagged call to confirm intent.",
            mitre=["T1027"],
            tags=["javascript", "obfuscation"],
        ))

    for keyword in js_data.get("Suspicious Keywords", []):
        if keyword in EXPLOIT_API_KEYWORDS:
            evidence.append(make_evidence(
                id=f"js.exploit_api.{_slug(keyword)}",
                category="JavaScript Execution",
                title="Known Exploit API Call",
                severity=SEVERITY_CRITICAL,
                confidence=CONFIDENCE_MEDIUM,
                evidence=f"JavaScript calls {keyword}(), an API with a documented "
                         f"history of abuse in malicious PDFs.",
                impact="Can be used to launch external content, exfiltrate form "
                       "data, or trigger other exploit-chain behavior.",
                recommendation=f"Locate every call to {keyword}() in the decoded "
                                f"script and determine its target/arguments.",
                mitre=["T1204.002"],
                tags=["javascript", "exploit-api"],
            ))

    # ---------------- Streams / Entropy ----------------

    for entry in stream_data.get("High Entropy Streams", []):
        obj_match = re.match(r"Stream (\d+)", entry)
        evidence.append(make_evidence(
            id=f"stream.high_entropy.{obj_match.group(1) if obj_match else _slug(entry)}",
            category="Stream Analysis",
            title="High-Entropy Stream",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_MEDIUM,
            evidence=entry,
            impact="Entropy above 7.2 suggests encrypted, packed, or otherwise "
                   "obfuscated content that may be concealing a payload.",
            recommendation="Extract and manually inspect this stream; attempt "
                            "decompression/decryption to reveal its true content.",
            mitre=["T1027.002"],
            obj=obj_match.group(0) if obj_match else None,
            tags=["stream", "entropy"],
        ))

    for entry in stream_data.get("Decompressed Findings", []):
        obj_match = re.match(r"Stream (\d+)", entry)
        evidence.append(make_evidence(
            id=f"stream.shellcode.{obj_match.group(1) if obj_match else _slug(entry)}",
            category="Stream Analysis",
            title="Shellcode Pattern",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_MEDIUM,
            evidence=entry,
            impact="Byte sequences consistent with shellcode (NOP sleds, common "
                   "prologues) indicate an exploit payload rather than "
                   "legitimate document content.",
            recommendation="Extract the decompressed stream and analyze it in "
                            "a disassembler or sandbox.",
            mitre=["T1055"],
            obj=obj_match.group(0) if obj_match else None,
            tags=["stream", "shellcode"],
        ))

    # ---------------- IOCs ----------------

    for url in ioc_data.get("URLs", []):
        evidence.append(make_evidence(
            id=f"ioc.url.{_slug(url)}",
            category="Indicator of Compromise",
            title="External URL Reference",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_MEDIUM,
            evidence=f"URL found inside the document: {url}",
            impact="May be used for phishing redirection, tracking, or as a "
                   "second-stage payload/C2 fetch location.",
            recommendation="Check the URL's reputation and, if malicious, "
                            "block it at the proxy/firewall.",
            mitre=["T1071.001"],
            tags=["ioc", "url"],
        ))

    for ip in ioc_data.get("IPs", []):
        evidence.append(make_evidence(
            id=f"ioc.ip.{_slug(ip)}",
            category="Indicator of Compromise",
            title="Embedded IP Address",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_MEDIUM,
            evidence=f"IP address found inside the document: {ip}",
            impact="A hardcoded IP is a stronger C2/exfiltration indicator than "
                   "a domain, since it bypasses DNS-based detection.",
            recommendation="Check the IP's reputation and block it at the "
                            "firewall if malicious.",
            mitre=["T1071.001"],
            tags=["ioc", "ip"],
        ))

    # ---------------- Embedded Files ----------------

    extracted = embedded_data.get("Extracted Files", [])

    if extracted:
        evidence.append(make_evidence(
            id="embedded.file",
            category="Embedded Content",
            title="Embedded File",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            evidence=f"{len(extracted)} file(s) extracted: "
                     f"{', '.join(extracted[:5])}" + (" ..." if len(extracted) > 5 else ""),
            impact="Embedded files can carry a secondary-stage payload that "
                   "executes after the PDF is opened or interacted with.",
            recommendation="Extract and statically analyze each embedded file "
                            "(hash it, check magic bytes, scan with AV/YARA).",
            mitre=["T1027"],
            tags=["embedded-file"],
        ))

    for sf in embedded_data.get("Suspicious Files", []):
        evidence.append(make_evidence(
            id=f"embedded.executable.{_slug(sf)}",
            category="Embedded Content",
            title="Embedded Executable",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence=sf,
            impact="A dangerous file extension embedded in a PDF is a strong "
                   "indicator of a dropper used to deliver malware once "
                   "extracted or executed.",
            recommendation="Treat the extracted file as live malware. Hash it "
                            "and submit to VirusTotal / detonate in a sandbox.",
            mitre=["T1204.002"],
            tags=["embedded-file", "executable"],
        ))

    # ---------------- Compression ----------------

    non_standard = [
        f for f in compression_data.get("Filters", [])
        if f not in STANDARD_COMPRESSION_FILTERS and f != "JBIG2Decode"
    ]

    if non_standard:
        evidence.append(make_evidence(
            id="compression.nonstandard_filter",
            category="Stream Analysis",
            title="Non-Standard Compression Filter",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_LOW,
            evidence=f"Filter(s) present: {', '.join(non_standard)}",
            impact="Uncommon filters are sometimes used to obscure payloads "
                   "from signature-based scanners, though many are benign.",
            recommendation="Confirm the filter is consistent with the "
                            "document's declared content (e.g. images vs. "
                            "arbitrary binary data).",
            tags=["compression"],
        ))

    if compression_data.get("JBIG2 Warning"):
        evidence.append(make_evidence(
            id="compression.jbig2",
            category="Known Exploit Vector",
            title="JBIG2Decode Filter (CVE-2010-0188)",
            severity=SEVERITY_CRITICAL,
            confidence=CONFIDENCE_HIGH,
            evidence=compression_data["JBIG2 Warning"],
            impact="JBIG2Decode has a documented history of exploitation for "
                   "remote code execution in vulnerable PDF readers.",
            recommendation="Verify the target reader's patch level and treat "
                            "this file as a likely exploit attempt.",
            mitre=["T1203"],
            tags=["compression", "exploit"],
        ))

    # ---------------- Encryption ----------------

    if encryption_data.get("Encrypted"):
        evidence.append(make_evidence(
            id="encryption.enabled",
            category="Structural Anomaly",
            title="Encrypted PDF",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            evidence="qpdf reports encryption parameters (R=/P=) on this file.",
            impact="Encryption can be legitimate, but is also used to hinder "
                   "static analysis of malicious content.",
            recommendation="Attempt to open with an empty password; if "
                            "successful, re-run analysis against the "
                            "decrypted copy.",
            mitre=["T1027"],
            tags=["encryption"],
        ))

    # ---------------- Forms / Actions ----------------

    if acroform_data.get("AcroForm Detected"):
        evidence.append(make_evidence(
            id="acroform.detected",
            category="Form / Action",
            title="AcroForm Present",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_HIGH,
            evidence="/AcroForm dictionary present with a real object reference.",
            impact="Combined with submitForm(), form fields can be used to "
                   "exfiltrate data to a remote server.",
            recommendation="Check whether any field action calls submitForm() "
                            "and, if so, where it submits to.",
            mitre=["T1114"],
            tags=["form"],
        ))

    if acroform_data.get("Additional Actions Found"):
        evidence.append(make_evidence(
            id="acroform.aa_trigger",
            category="Auto-Execution Trigger",
            title="/AA Additional Action Trigger",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            evidence="/AA dictionary present as a real object reference.",
            impact="Fires an associated action automatically on events such "
                   "as page open/close — no user interaction required.",
            recommendation="Identify what the /AA entry triggers and inspect "
                            "it directly.",
            mitre=["T1204"],
            tags=["form", "auto-exec"],
        ))

    if acroform_data.get("XFA Form Detected"):
        evidence.append(make_evidence(
            id="acroform.xfa",
            category="Form / Action",
            title="XFA Form Present",
            severity=SEVERITY_MEDIUM,
            confidence=CONFIDENCE_HIGH,
            evidence="/XFA dictionary present as a real object reference.",
            impact="XFA forms have historically been used as a delivery "
                   "mechanism in spearphishing-based exploit chains.",
            recommendation="Extract and review the embedded XFA XML for "
                            "scripted content.",
            mitre=["T1566.001"],
            tags=["form"],
        ))

    return evidence
