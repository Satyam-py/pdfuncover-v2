#!/usr/bin/env python3
"""
main.py — PDFUncover CLI entry point.

Wires together every existing module into one complete pipeline:

    metadata extraction  (modules.metadata)
    embedded/object analysis, JS, IOCs, threat-intel enrichment
                          (modules.embedded_extraction -> modules.parsers.*)
    threat scoring        (modules.analyzer)
    threat correlation     (modules.correlation)
    evidence graph         (modules.evidence_explorer)
    attack chain           (modules.attack_chain)
    report generation      (modules.report — Professional Report Engine)

and renders progress/results to a colored terminal UI.

No detection/scoring logic lives here — this module is purely
orchestration + presentation. Every module above already exists and
is used through its existing public API; nothing here duplicates
logic that already lives in one of those modules.

CONFIG CONSOLIDATION NOTE: API key loading/saving delegates to
modules.app_config — the single configuration source shared with
modules/threat_intel_pipeline.py's provider credentials.

SHIM REMOVAL NOTE: the VirusTotal hash lookup previously went through
modules.virustotal.query_virustotal() — a temporary compatibility
shim that adapted the typed provider's ProviderResult back into a
flat dict. That shim is gone. This file now calls the typed provider
(modules.threat_intel.providers.virustotal.lookup_hash) directly and
does the same adaptation itself, in _vt_hash_result_to_metadata()
below — same output shape, same call site, one fewer file in between.
"""

import argparse
import json
import logging
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from colorama import Fore, Style, init

from modules.metadata import extract_metadata
from modules.embedded_extraction import extract_embedded_objects
from modules.analyzer import analyze_results
from modules.threat_intel.providers.virustotal import lookup_hash as vt_lookup_hash
from modules.threat_intel.models import LookupError
from modules.correlation import ThreatCorrelationEngine
from modules.evidence_explorer import build_evidence_graph
from modules.attack_chain import reconstruct_attack_chain
from modules.report import generate_professional_report
from modules.app_config import load_config, save_api_key
from modules.parsers.evidence import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)

init(autoreset=True)


# ==========================================
# COLORS
# ==========================================

R  = Fore.RED     + Style.BRIGHT
G  = Fore.GREEN   + Style.BRIGHT
Y  = Fore.YELLOW  + Style.BRIGHT
C  = Fore.CYAN    + Style.BRIGHT
W  = Fore.WHITE   + Style.BRIGHT
M  = Fore.MAGENTA + Style.BRIGHT
D  = Fore.WHITE   + Style.DIM
RS = Style.RESET_ALL


# ==========================================
# LOGGING
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/main.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# VIRUSTOTAL HASH LOOKUP (typed provider, adapted for metadata output)
# ==========================================
#
# Replaces the old modules.virustotal.query_virustotal() shim. Calls
# the typed VirusTotal provider directly and reshapes its
# ProviderResult into the exact same flat dict shape the shim used to
# produce, so metadata["VirusTotal"] — and everything that reads it
# (modules.analyzer._score_virustotal / _build_virustotal_evidence,
# modules.evidence_explorer's hash-level VT artifact) — is byte-for-byte
# unchanged:
#
#   found, no detections   -> {"Found": True, "Malicious": 0, "Suspicious": 0,
#                               "Harmless": N, "Undetected": N, "Total": N,
#                               "Link": "https://..."}
#   hash not on record      -> {"Found": True, "Known Sample": False,
#                               "Message": "Hash not found in VirusTotal"}
#   lookup failed            -> {"Found": False, "Error": "<reason>"}

def query_virustotal(sha256: str, api_key: str) -> Dict[str, Any]:
    """Typed-provider-backed replacement for the old shim of the same name."""

    result = vt_lookup_hash(sha256, api_key)

    if not result.success:

        if result.error == LookupError.NOT_FOUND:
            return {
                "Found": True,
                "Known Sample": False,
                "Message": "Hash not found in VirusTotal",
            }

        return {
            "Found": False,
            "Error": result.error.value if result.error else "unknown error",
        }

    rep = result.data.reputation

    return {
        "Found": True,
        "Malicious": rep.malicious,
        "Suspicious": rep.suspicious,
        "Harmless": rep.harmless,
        "Undetected": rep.undetected,
        "Total": rep.total,
        "Link": rep.permalink,
    }


# ==========================================
# BANNER ARTS
# ==========================================

ARTS = [

    (
        f"{R}\n"
        f"   +------------------------------------------+\n"
        f"   |  {W}PDFUNCOVER{R} v1.0  --  by Research Lab     |\n"
        f"   +---------------------+--------------------+\n"
        f"   |{RS}  {C}_______ _______{R}   |{RS}  {Y}|'|{RS}   {R}|\n"
        f"   |{RS} {C}|  ___  |  ___  |{R}  |{RS}  {Y}| JS ENGINE  |{RS}   {R}|\n"
        f"   |{RS} {C}| |{W}pdf{C}| | {W}>_{C}  |{R}  |{RS}  {Y}|  eval()    |{RS}   {R}|\n"
        f"   |{RS} {C}| |___| |______ |{R}  |{RS}  {Y}|  unescape  |{RS}   {R}|\n"
        f"   |{RS} {C}|_______|_______|{R}  |{RS}  {Y}|____________|{RS}   {R}|\n"
        f"   |{RS}                     {R}|{RS}  {Y}\\(@)(@)(@)(@)/{RS}   {R}|\n"
        f"   +---------------------+--------------------+{RS}"
    ),

   (
    f"{G}\n"
    f"▄▄▄··▄▄▄▄  ·▄▄▄•▄• ▄▌ ▐ ▄  ▄▄·       ▌ ▐·▄▄▄ .▄▄▄\n"
    f"▐█ ▄███▪ ██ ▐▄▄·█▪██▌•█▌▐█▐█ ▌▪▪     ▪█·█▌▀▄.▀·▀▄ █·\n"
    f" ██▀·▐█· ▐█▌██▪ █▌▐█▌▐█▐▐▌██ ▄▄ ▄█▀▄ ▐█▐█•▐▀▀▪▄▐▀▀▄\n"
    f"▐█▪·•██. ██ ▐█▌.▐█▄█▌██▐█▌▐███▌▐█▌.▐▌ ███ ▐█▄▄▌▐█•█▌\n"
    f".▀   ▀▀▀▀▀• ▀▀▀  ▀▀▀ ▀▀ █▪·▀▀▀  ▀█▄▀▪. ▀   ▀▀▀ .▀  ▀\n"
    f"\n"
    f"{R}        [ PDF MALWARE ANALYSIS TOOLKIT ]\n"
    f"{RS}"
    ),

    (
        f"{C}\n"
        f"   +------------------------------------------+\n"
        f"   |  {W}PDFUNCOVER{C} v1.0  --  by Research Lab     |\n"
        f"   +------------------------------------------+\n"
        f"   |{RS}  {Y}/\\_/\\{C}   {R}sniffing your PDFs since 2024  {C}  |\n"
        f"   |{RS} {Y}( >.< ){C}                                   {C}  |\n"
        f"   |{RS}  {Y}(___)  {C}  {G}[+]{RS} header  {G}[+]{RS} streams            {C}  |\n"
        f"   |{RS}          {G}[+]{RS} js      {G}[+]{RS} iocs               {C}  |\n"
        f"   |{RS}          {G}[+]{RS} entropy {G}[+]{RS} embedded           {C}  |\n"
        f"   |{RS}          {G}[+]{RS} forms   {G}[+]{RS} mitre att&ck       {C}  |\n"
        f"   +------------------------------------------+{RS}"
    ),

]


# ==========================================
# BANNER
# ==========================================

def banner() -> None:
    """Clear the screen and print a random ASCII-art banner + summary bar."""

    os.system("clear")
    art = random.choice(ARTS)
    print(art)
    print(f"\n{D}  {'─' * 50}{RS}")
    print(f"  {D}={RS} [ {W}PDFUNCOVER — PDF Malware Analysis Toolkit{RS}  ]")
    print(f"  {D}={RS} [ {D}metadata / ioc / streams / entropy / forms{RS}  ]")
    print(f"  {D}={RS} [ {D}correlation / evidence graph / attack chain{RS}  ]")
    print(f"  {D}={RS} [ {D}output: json / markdown / html / txt reports{RS}  ]")
    print(f"  {D}+{RS} --=[ {D}for educational and research use only{RS}   ]")
    print(f"{D}  {'─' * 50}{RS}\n")


# ==========================================
# OUTPUT HELPERS
# ==========================================
#
# Design rules for this section (presentation only — see module docstring
# for the "no logic/scoring/detection changes" guarantee that still holds):
#
#   - Informational output (metadata, embedded-object dumps, config/status
#     lines) is rendered in neutral/dim tones. It describes what the tool
#     did or observed, not a verdict, so it never competes visually with
#     real findings.
#   - Color is reserved for things that represent an actual finding: a
#     Suspicious Finding, an Evidence Report item, the threat verdict, or
#     an explicit warning/error.
#   - Severity drives color for findings, using the same severities the
#     analyzer already assigns (SEVERITY_CRITICAL..SEVERITY_INFO / the
#     CLEAN..CRITICAL threat levels) — nothing here invents new levels.
#

# Threat-level verdict colors (unchanged mapping, centralized)
VERDICT_COLOR = {
    "CLEAN":    G,
    "LOW":      C,
    "MEDIUM":   Y,
    "HIGH":     R,
    "CRITICAL": M,
}

# Evidence-severity colors, ordered from most to least severe
SEVERITY_COLOR = {
    SEVERITY_CRITICAL: M,
    SEVERITY_HIGH:      R,
    SEVERITY_MEDIUM:    Y,
    SEVERITY_LOW:        C,
    SEVERITY_INFO:       D,
}

SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

# Confidence colors for the Attack Chain section
CONFIDENCE_COLOR = {
    "High":   R,
    "Medium": Y,
    "Low":    C,
}

# Keys that are informational duplicates of what the grouped findings /
# evidence report already renders more usefully — skipped only in the
# raw dictionary dump so nothing is printed twice.
DICTIONARY_SKIP_KEYS = frozenset({"Evidence", "Suspicious Flags"})


def print_section(title: str) -> None:
    print(f"\n{D}{'=' * 70}")
    print(f"{W}{Style.BRIGHT}[ {title} ]{RS}")
    print(f"{D}{'=' * 70}{RS}")


def status(msg: str) -> None:
    print(f"{D}[{RS}{C}+{D}]{RS} {D}{msg}{RS}")


def warning(msg: str) -> None:
    print(f"{D}[{RS}{Y}!{D}]{RS} {Y}{msg}{RS}")


def error(msg: str) -> None:
    print(f"{D}[{RS}{R}x{D}]{RS} {R}{msg}{RS}")


def print_dictionary(
    data: Dict[str, Any],
    indent: int = 0,
    skip_keys: frozenset = DICTIONARY_SKIP_KEYS,
) -> None:
    """
    Recursively print a nested dict as neutral, informational output.
    Skips empty lists, None values, and skip_keys cleanly. This is for
    "here's what we observed" data (metadata, embedded-object dumps) —
    it deliberately does not use finding/severity colors.
    """

    if not isinstance(data, dict):
        return

    spacing = " " * indent

    for key, value in data.items():

        # Skip internal keys and anything rendered elsewhere (findings)
        if key.startswith("_") or key in skip_keys:
            continue

        if isinstance(value, dict):

            print(f"{spacing}{D}{key}{RS}")
            print_dictionary(value, indent + 4, skip_keys)

        elif isinstance(value, list):

            if not value:
                continue

            # Nested dicts (e.g. raw Evidence objects) belong in the
            # grouped findings view, not this informational dump.
            if all(isinstance(item, dict) for item in value):
                continue

            print(f"{spacing}{D}{key}{RS}")

            for item in value:
                print(f"{' ' * (indent + 4)}{D}·{RS} {W}{item}{RS}")

        elif value is None or value == "":
            continue

        else:
            print(
                f"{spacing}{D}{key:<32}{RS}: {W}{value}{RS}"
            )


def print_investigation_summary(
    pdf_path: str,
    metadata: Dict[str, Any],
    analysis: Dict[str, Any],
) -> None:
    """
    Compact, scannable summary of the investigation: what was scanned,
    the verdict, and a one-line breakdown of findings by severity.
    """

    threat = analysis.get("Threat Level", "UNKNOWN")
    score  = analysis.get("Risk Score", 0)
    color  = VERDICT_COLOR.get(threat, M)

    evidence_report = analysis.get("Evidence Report") or {}
    summary = evidence_report.get("summary", {})

    print(f"\n{D}{'─' * 70}{RS}")
    print(f"  {W}{Style.BRIGHT}Investigation Summary{RS}")
    print(f"{D}{'─' * 70}{RS}")
    print(f"  {D}{'Target':<14}{RS}: {W}{metadata.get('File Name', pdf_path)}{RS}")
    print(f"  {D}{'SHA256':<14}{RS}: {D}{metadata.get('SHA256', 'N/A')}{RS}")
    print(f"  {D}{'Threat Level':<14}{RS}: {color}{Style.BRIGHT}{threat}{RS}")
    print(f"  {D}{'Risk Score':<14}{RS}: {color}{Style.BRIGHT}{score}/100{RS}")

    counts = " ".join(
        f"{SEVERITY_COLOR.get(sev, W)}{sev}:{summary.get(sev, 0)}{RS}"
        for sev in SEVERITY_ORDER
        if summary.get(sev, 0)
    )

    if counts:
        print(f"  {D}{'Findings':<14}{RS}: {counts}")
    else:
        print(f"  {D}{'Findings':<14}{RS}: {G}none{RS}")

    print(f"{D}{'─' * 70}{RS}")


def print_findings(analysis: Dict[str, Any]) -> None:
    """
    Render the investigation's findings grouped by severity. Uses the
    Evidence Report when available (richer, per-item detail); falls back
    to the flat Suspicious Findings list otherwise. Only real findings
    are colored — an empty result is shown neutrally as "no findings".
    """

    evidence_report = analysis.get("Evidence Report") or {}
    evidence = evidence_report.get("evidence", [])

    if evidence:

        for sev in SEVERITY_ORDER:

            group = [e for e in evidence if e.get("severity") == sev]

            if not group:
                continue

            color = SEVERITY_COLOR.get(sev, W)
            print(f"\n  {color}{Style.BRIGHT}{sev} ({len(group)}){RS}")

            for item in group:
                title = item.get("title") or item.get("id", "Finding")
                print(f"    {color}●{RS} {W}{title}{RS}")

                detail = item.get("evidence")
                if detail:
                    print(f"      {D}{detail}{RS}")

                mitre = item.get("mitre")
                if mitre:
                    print(f"      {D}MITRE: {', '.join(mitre)}{RS}")

        print()
        return

    # Fallback: analyzer ran without an Evidence Report — use the flat list.
    findings = analysis.get("Suspicious Findings", [])

    if not findings:
        print(f"\n  {G}No suspicious findings.{RS}\n")
        return

    print()
    for finding in findings:
        print(f"  {R}●{RS} {W}{finding}{RS}")

    mitre = analysis.get("MITRE ATT&CK", [])
    if mitre:
        print(f"\n  {D}MITRE ATT&CK{RS}")
        for technique in mitre:
            print(f"    {D}·{RS} {W}{technique}{RS}")

    print()


def print_correlated_findings(correlation_result: Dict[str, Any]) -> None:
    """
    Render the Threat Correlation Engine's cross-signal findings, plus
    the Overall IOC Reputation summary. Purely presentational — every
    field is copied verbatim from modules.correlation output.
    """

    findings = correlation_result.get("Correlated Findings", [])
    reputation = correlation_result.get("Overall IOC Reputation", {})
    score = correlation_result.get("Correlation Score", 0)

    if reputation.get("Total IOCs Checked"):
        print(
            f"  {D}Overall IOC Reputation{RS}: "
            f"{W}{reputation.get('Overall Verdict', 'unknown')}{RS} "
            f"{D}(checked {reputation.get('Total IOCs Checked', 0)}, "
            f"malicious {reputation.get('Malicious', 0)}, "
            f"confidence {reputation.get('Confidence', 'None')}){RS}"
        )

    print(f"  {D}Correlation Score{RS}: {W}{score}/100{RS}")

    if not findings:
        print(f"\n  {G}No correlated (cross-signal) findings.{RS}\n")
        return

    print()
    for finding in findings:
        sev = finding.get("Severity", SEVERITY_INFO)
        color = SEVERITY_COLOR.get(sev, W)
        print(f"  {color}{Style.BRIGHT}[{sev}]{RS} {W}{finding.get('Title', 'Finding')}{RS}")
        print(f"    {D}{finding.get('Evidence', '')}{RS}")
        rec = finding.get("Recommendation")
        if rec:
            print(f"    {D}Recommendation: {RS}{W}{rec}{RS}")
        mitre = finding.get("MITRE ATT&CK")
        if mitre:
            print(f"    {D}MITRE: {', '.join(mitre)}{RS}")
        print()


def print_attack_chain(attack_chain_result: Dict[str, Any]) -> None:
    """
    Render the reconstructed attack chain, in narrative (step) order.
    Every field is copied verbatim from modules.attack_chain output.
    """

    chain = attack_chain_result.get("Attack Chain", [])

    if not chain:
        print(f"\n  {G}No static attack-chain pattern reconstructed.{RS}\n")
        return

    print()
    for step in chain:
        conf = step.get("confidence", "Low")
        color = CONFIDENCE_COLOR.get(conf, W)
        print(
            f"  {D}Step {step.get('step')}{RS} "
            f"{color}{Style.BRIGHT}{step.get('title')}{RS} "
            f"{D}(confidence: {conf}){RS}"
        )
        print(f"    {W}{step.get('description', '')}{RS}")

        for ev in step.get("evidence", []):
            print(f"      {D}· {ev}{RS}")

        mitre = step.get("mitre")
        if mitre:
            print(f"    {D}MITRE: {', '.join(mitre)}{RS}")
        print()


def print_verdict(threat: str, score: int) -> None:
    """
    Print final verdict with appropriate color per threat level.
    """

    color = VERDICT_COLOR.get(threat, M)

    verdict_art = {
        "CLEAN":    f"{G}  [✓] No significant threats detected.",
        "LOW":      f"{C}  [~] Low risk. Review findings.",
        "MEDIUM":   f"{Y}  [!] Medium risk. Treat with caution.",
        "HIGH":     f"{R}  [!!] HIGH RISK. Do not open this file.",
        "CRITICAL": f"{M}  [!!!] CRITICAL. Likely malicious payload.",
    }

    print(f"\n{D}{'=' * 70}{RS}")
    print(f"{color}{Style.BRIGHT}  Threat Level : {threat}{RS}")
    print(f"{color}{Style.BRIGHT}  Risk Score   : {score}/100{RS}")
    print(verdict_art.get(threat, ""))
    print(f"{D}{'=' * 70}{RS}")


def validate_input(pdf_path: Optional[str]) -> Tuple[bool, str]:
    """
    Validate PDF path before analysis.
    Returns (is_valid, error_message).
    """

    if not pdf_path:
        return False, "No PDF file specified"

    path = Path(pdf_path)

    if not path.exists():
        return False, f"File not found: {pdf_path}"

    if not path.is_file():
        return False, f"Not a file: {pdf_path}"

    if path.stat().st_size == 0:
        return False, f"File is empty: {pdf_path}"

    if path.suffix.lower() not in (".pdf", ""):
        warning(f"File extension is not .pdf — analyzing anyway")

    max_size = 50 * 1024 * 1024  # 50MB limit

    if path.stat().st_size > max_size:
        return False, (
            f"File too large ({path.stat().st_size / 1024 / 1024:.1f} MB). "
            f"Max supported: 50MB"
        )

    return True, ""


# ==========================================
# NORMALIZATION
# ==========================================

def normalize_with_qpdf(pdf_path: str, output_dir: str) -> str:
    """
    Attempt to normalize a PDF with qpdf (--qdf, object streams disabled).
    Returns the normalized path on success, or the original path unchanged
    if qpdf is unavailable or normalization fails. Emits the same
    status/warning messages as before.
    """

    if not shutil.which("qpdf"):
        warning("qpdf not installed — skipping normalization")
        return pdf_path

    status("Normalizing PDF with qpdf...")

    os.makedirs(output_dir, exist_ok=True)
    normalized_pdf = os.path.join(output_dir, "normalized.pdf")

    result = subprocess.run(
        [
            "qpdf", "--qdf",
            "--object-streams=disable",
            pdf_path,
            normalized_pdf
        ],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        status(f"Normalized : {normalized_pdf}")
        return normalized_pdf

    warning(f"qpdf normalization failed: {result.stderr.strip()}")
    warning("Continuing with original file")
    return pdf_path


# ==========================================
# ARGUMENT PARSING
# ==========================================

def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser (identical flags/help text,
    plus --formats / --no-attack-chain / --no-correlation for the
    now-wired-in investigation stages)."""

    parser = argparse.ArgumentParser(
        prog="pdfuncover",
        formatter_class=argparse.RawTextHelpFormatter,
        description=f"""{R}{Style.BRIGHT}
PDFUNCOVER — PDF Malware Analysis Toolkit

Examples:
  python main.py sample.pdf
  python main.py malware.pdf --normalize
  python main.py malware.pdf --no-banner
  python main.py malware.pdf --output-dir output/ --formats json html

Features:
  • PDF Header Validation
  • Metadata Extraction & Anomaly Detection
  • JavaScript Detection + JS Content Preview
  • Stream Entropy Analysis (Shannon)
  • Shellcode Pattern Detection
  • IOC Extraction (URLs / Domains / IPs) + Threat Intelligence
  • Embedded File Extraction (dual strategy)
  • AcroForm / AA / XFA Detection
  • Threat Correlation Engine (cross-signal findings)
  • Evidence Explorer (investigation graph)
  • Attack Chain Reconstruction
  • MITRE ATT\\&CK Technique Mapping
  • Multi-format Report Output (JSON / Markdown / HTML / TXT)
{RS}"""
    )

    parser.add_argument(
        "pdf",
        nargs="?",
        help="PDF file to analyze"
    )

    parser.add_argument(
        "--normalize",
        action="store_true",
        help="Normalize PDF with qpdf before analysis (recommended for obfuscated PDFs)"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner (useful for scripting / piping output)"
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="Base output directory (default: output/)"
    )

    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "markdown", "md", "html", "text", "txt"],
        default=["json", "markdown", "html", "text"],
        help="Report formats to generate (default: json markdown html text)"
    )

    parser.add_argument(
        "--no-correlation",
        action="store_true",
        help="Skip the Threat Correlation Engine stage"
    )

    parser.add_argument(
        "--no-attack-chain",
        action="store_true",
        help="Skip Attack Chain Reconstruction"
    )

    parser.add_argument(
        "--add-api-key",
        metavar="KEY",
        help="Store VirusTotal API key"
    )

    return parser


# ==========================================
# MAIN
# ==========================================

def main() -> None:

    parser = build_arg_parser()
    args = parser.parse_args()

    # ==========================================
    # API KEY REGISTRATION (early exit)
    # ==========================================

    if args.add_api_key:
        save_api_key(args.add_api_key)
        print(f"{D}[+]{RS} VirusTotal API key saved")
        sys.exit(0)

    # ==========================================
    # BANNER
    # ==========================================

    if not args.no_banner:
        banner()
    else:
        print(f"{D}[PDFUNCOVER]{RS} Starting analysis...\n")

    # ==========================================
    # INPUT VALIDATION
    # ==========================================

    valid, err = validate_input(args.pdf)

    if not valid:
        error(err)
        if not args.pdf:
            print(f"\n{D}Usage: python main.py <file.pdf> [--output-dir output/]{RS}\n")
        sys.exit(1)

    pdf_path = args.pdf
    status(f"Target     : {pdf_path}")

    try:
        file_size = Path(pdf_path).stat().st_size
        status(f"File size  : {file_size / 1024:.1f} KB")
    except OSError:
        pass

    # ==========================================
    # OUTPUT DIRECTORIES
    # ==========================================

    output_dir = args.output_dir
    reports_dir = os.path.join(output_dir, "reports")

    try:
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(reports_dir, exist_ok=True)
    except OSError as e:
        log.error(f"Could not create output directories: {e}")
        error(f"Could not create output directory '{output_dir}': {e}")
        sys.exit(1)

    # ==========================================
    # NORMALIZATION
    # ==========================================

    if args.normalize:
        pdf_path = normalize_with_qpdf(pdf_path, output_dir)

    # ==========================================
    # METADATA (+ VirusTotal hash lookup, if configured)
    # ==========================================
    #
    # VirusTotal is queried here (as before) and folded back into the
    # metadata dict as metadata["VirusTotal"], since that is the exact
    # shape modules.analyzer (_score_virustotal /
    # _build_virustotal_evidence) and modules.evidence_explorer already
    # expect and read from — wiring it in, not new detection logic. The
    # lookup itself now goes straight to the typed VirusTotal provider
    # via query_virustotal() defined above (no shim in between).

    status("Extracting metadata...")

    try:
        metadata = extract_metadata(pdf_path)
    except Exception as e:
        log.error(f"Metadata extraction failed: {e}")
        error(f"Metadata extraction failed: {e}")
        metadata = {}

    vt_results: Dict[str, Any] = {}
    api_key = load_config().get("virustotal_api_key")

    if api_key:

        sha256 = metadata.get("SHA256")

        if sha256 and sha256 != "Error":
            status("Querying VirusTotal...")
            try:
                vt_results = query_virustotal(sha256, api_key)
            except Exception as e:
                log.error(f"VirusTotal query failed: {e}")
                vt_results = {"Found": False, "Error": str(e)}

            metadata["VirusTotal"] = vt_results
    else:
        status("No VirusTotal API key configured — skipping (offline analysis)")

    print_section("METADATA ANALYSIS")
    print_dictionary(metadata)

    if vt_results and vt_results.get("Found"):
        print_section("VIRUSTOTAL")
        print_dictionary(vt_results)
    else:
        print(f"\n{D}No VirusTotal results{RS}")

    # ==========================================
    # EMBEDDED OBJECT ANALYSIS
    # ==========================================
    #
    # This single call already runs every parser (header, streams, JS,
    # IOCs, embedded files, images, compression, encryption, AcroForm)
    # and performs IOC threat-intelligence enrichment internally
    # (modules.parsers.iocs -> modules.threat_intel_pipeline ->
    # modules.threat_intel.engine) — so IOC lookups happen exactly once
    # per run, with no duplicate lookups downstream.

    status("Analyzing embedded objects (header/streams/js/iocs/forms)...")

    try:
        embedded_results = extract_embedded_objects(pdf_path)
    except Exception as e:
        log.error(f"Embedded extraction failed: {e}")
        error(f"Embedded extraction failed: {e}")
        embedded_results = {}

    print_section("EMBEDDED OBJECT ANALYSIS")
    print_dictionary(embedded_results)

    # ==========================================
    # THREAT ANALYSIS (scoring, MITRE mapping, Evidence Report)
    # ==========================================

    status("Running threat analysis...")

    try:
        analysis = analyze_results(metadata, embedded_results)
    except Exception as e:
        log.error(f"Analysis failed: {e}")
        error(f"Threat analysis failed: {e}")
        analysis = {
            "Threat Level": "UNKNOWN",
            "Risk Score": 0,
            "Suspicious Findings": [],
            "MITRE ATT&CK": []
        }

    print_section("THREAT ANALYSIS")
    print_investigation_summary(pdf_path, metadata, analysis)
    print_findings(analysis)

    # ==========================================
    # THREAT CORRELATION ENGINE
    # ==========================================
    #
    # Cross-references already-computed per-category results +
    # threat-intel to synthesize compound findings analyzer.py's
    # per-category scoring doesn't see on its own (e.g. OpenAction +
    # a malicious URL together). Never breaks the pipeline — a failure
    # here degrades to an empty correlation result.

    correlation_result: Dict[str, Any] = {
        "Overall IOC Reputation": {}, "Correlated Findings": [], "Correlation Score": 0
    }

    if not args.no_correlation:

        status("Running threat correlation engine...")

        try:
            correlation_result = ThreatCorrelationEngine().correlate(
                metadata=metadata,
                embedded_analysis=embedded_results.get("Embedded Files", {}),
                javascript_analysis=embedded_results.get("JavaScript", {}),
                stream_analysis=embedded_results.get("Streams", {}),
                acroform_analysis=embedded_results.get("AcroForm", {}),
                compression_analysis=embedded_results.get("Compression", {}),
                iocs=embedded_results.get("IOCs", {}),
            )
        except Exception as e:
            log.error(f"Threat correlation failed: {e}")
            warning(f"Threat correlation failed: {e}")

        print_section("THREAT CORRELATION")
        print_correlated_findings(correlation_result)

    # ==========================================
    # ATTACK CHAIN RECONSTRUCTION
    # ==========================================
    #
    # Reconstructs the most likely attack chain from static evidence
    # already produced above (metadata, embedded_results, analysis,
    # correlation_result). Purely additive — never rescored or
    # re-detected here.

    attack_chain_result: Dict[str, Any] = {"Attack Chain": []}

    if not args.no_attack_chain:

        status("Reconstructing attack chain...")

        try:
            attack_chain_result = reconstruct_attack_chain(
                metadata=metadata,
                embedded_results=embedded_results,
                analysis=analysis,
                correlation_result=correlation_result,
            )
        except Exception as e:
            log.error(f"Attack chain reconstruction failed: {e}")
            warning(f"Attack chain reconstruction failed: {e}")

        print_section("ATTACK CHAIN RECONSTRUCTION")
        print_attack_chain(attack_chain_result)

    # ==========================================
    # EVIDENCE EXPLORER (investigation graph)
    # ==========================================

    status("Building evidence graph...")

    evidence_graph: Dict[str, Any] = {"Artifacts": [], "Relationships": [], "Artifact Count": 0}

    try:
        evidence_graph = build_evidence_graph(
            pdf_path,
            metadata=metadata,
            embedded_results=embedded_results,
            analysis=analysis,
            correlation_result=correlation_result,
        )
        status(
            f"Evidence graph built : {evidence_graph.get('Artifact Count', 0)} "
            f"artifact(s), {len(evidence_graph.get('Relationships', []))} relationship(s)"
        )
    except Exception as e:
        log.error(f"Evidence graph build failed: {e}")
        warning(f"Evidence graph build failed: {e}")

    # ==========================================
    # ATTACK CHAIN — saved alongside the reports
    # ==========================================
    #
    # The attack chain is now included in every report format via the
    # Professional Report Engine (see modules/report/model.py). The
    # separate JSON file is preserved as a standalone artifact alongside
    # the other generated reports so consumers that already rely on it
    # are unaffected.

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if attack_chain_result.get("Attack Chain"):
        try:
            chain_path = os.path.join(reports_dir, f"attack_chain_{timestamp}.json")
            with open(chain_path, "w", encoding="utf-8") as f:
                json.dump(attack_chain_result, f, indent=2, default=str)
            status(f"Attack chain saved : {chain_path}")
        except OSError as e:
            log.error(f"Failed to write attack chain JSON: {e}")
            warning(f"Failed to save attack chain JSON: {e}")

    # ==========================================
    # PROFESSIONAL REPORT ENGINE (JSON / Markdown / HTML / Text)
    # ==========================================

    status("Generating reports (json/markdown/html/text)...")

    try:
        written_reports = generate_professional_report(
            pdf_path=pdf_path,
            metadata=metadata,
            embedded_results=embedded_results,
            analysis=analysis,
            evidence_graph=evidence_graph,
            correlation_result=correlation_result,
            attack_chain_result=attack_chain_result,
            output_dir=reports_dir,
            formats=args.formats,
        )
    except Exception as e:
        log.error(f"Report generation failed: {e}")
        written_reports = {}

    if written_reports:
        for fmt, path in written_reports.items():
            status(f"Report ({fmt:<8}) : {path}")
    else:
        warning("Report generation failed — check logs/report.log")

    # ==========================================
    # FINAL VERDICT
    # ==========================================

    print_section("FINAL VERDICT")

    threat = analysis.get("Threat Level", "UNKNOWN")
    score  = analysis.get("Risk Score", 0)

    print_verdict(threat, score)
    print(f"\n{G}[✓] Analysis completed{RS}\n")


# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user{RS}")
        sys.exit(0)
    except Exception as e:
        log.error(f"Unhandled exception: {e}", exc_info=True)
        print(f"\n{R}[!] Unexpected error: {e}{RS}")
        print(f"{Y}[!] Check logs/main.log for details{RS}")
        sys.exit(1)