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

HASH ENRICHMENT CONSOLIDATION NOTE (Step 9): Direct VirusTotal hash
lookups (via query_virustotal() and vt_lookup_hash) have been removed.
Metadata file hashes are now extracted as IOCs and enriched through
the standard threat-intelligence pipeline alongside all other IOC types
(URLs, domains, IPs, embedded file hashes). This provides:
- One canonical enrichment path (Engine + providers)
- Consistent treatment of all IOC types
- No duplicate VirusTotal lookups
- Hash verdicts available via embedded_results["IOCs"]["Threat Intelligence"]

The VirusTotal API key is loaded exclusively by modules.app_config and
consumed by the Threat Intelligence Engine. main.py no longer prompts
for or uses the key directly — setup_virustotal_key() is retained only
as a utility for interactive key configuration if needed in future CLI
extensions.
"""

import argparse
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from colorama import Fore, Style, init

from modules.metadata import extract_metadata
from modules.embedded_extraction import extract_embedded_objects
from modules.analyzer import analyze_results
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
    print(f"  {D}={'─' * 50}{RS}\n")


# ==========================================
# STATUS DISPLAY HELPERS
# ==========================================

def status(msg: str) -> None:
    """Print a [*] status message."""
    print(f"{G}[*]{RS} {msg}")

def success(msg: str) -> None:
    """Print a [+] success message."""
    print(f"{G}[+]{RS} {msg}")

def warning(msg: str) -> None:
    """Print a [!] warning message."""
    print(f"{Y}[!]{RS} {msg}")

def error(msg: str) -> None:
    """Print a [-] error message."""
    print(f"{R}[-]{RS} {msg}")


# ==========================================
# SECTION PRINTING
# ==========================================

def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{M}{'═' * 50}{RS}")
    print(f"{M}║{RS} {W}{title:^48}{M} ║{RS}")
    print(f"{M}{'═' * 50}{RS}\n")


def print_dictionary(data: Dict[str, Any], indent: int = 0) -> None:
    """Pretty-print a nested dictionary."""
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            print(f"{prefix}{C}{key}:{RS}")
            print_dictionary(value, indent + 1)
        elif isinstance(value, list):
            if value:
                print(f"{prefix}{C}{key}:{RS}")
                for item in value:
                    if isinstance(item, dict):
                        print_dictionary({"  ": item}, indent + 1)
                    else:
                        print(f"{prefix}  {G}•{RS} {item}")
            else:
                print(f"{prefix}{C}{key}:{RS} {D}(none){RS}")
        else:
            print(f"{prefix}{C}{key}:{RS} {value}")


def print_investigation_summary(pdf_path: str, metadata: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    """Print investigation summary."""
    print(f"{W}File:{RS} {pdf_path}")
    if metadata:
        print(f"{W}Size:{RS} {metadata.get('File Size', 'Unknown')} bytes")
        print(f"{W}Title:{RS} {metadata.get('Title', 'N/A')}")
        print(f"{W}Author:{RS} {metadata.get('Author', 'N/A')}")
    print(f"{W}Threat Level:{RS} {analysis.get('Threat Level', 'UNKNOWN')}")
    print(f"{W}Risk Score:{RS} {analysis.get('Risk Score', 0)}/100")


def print_findings(analysis: Dict[str, Any]) -> None:
    """Print suspicious findings and MITRE ATT&CK mappings."""
    findings = analysis.get("Suspicious Findings", [])
    if findings:
        print(f"\n{W}Suspicious Findings:{RS}")
        for finding in findings:
            severity = finding.get("Severity", "INFO")
            title = finding.get("Title", "Unknown")
            color = R if severity == "CRITICAL" else Y if severity in ["HIGH", "MEDIUM"] else W
            print(f"  {color}[{severity}]{RS} {title}")

    mitre = analysis.get("MITRE ATT&CK", [])
    if mitre:
        print(f"\n{W}MITRE ATT&CK Mapping:{RS}")
        for tactic in mitre:
            print(f"  {C}{tactic}{RS}")


def print_correlated_findings(correlation: Dict[str, Any]) -> None:
    """Print correlated findings."""
    findings = correlation.get("Correlated Findings", [])
    score = correlation.get("Correlation Score", 0)
    
    print(f"{W}Correlation Score:{RS} {score}/100")
    
    if findings:
        print(f"\n{W}Correlated Findings:{RS}")
        for finding in findings:
            print(f"  {G}•{RS} {finding}")


def print_attack_chain(result: Dict[str, Any]) -> None:
    """Print reconstructed attack chain."""
    chain = result.get("Attack Chain", [])
    if chain:
        for i, step in enumerate(chain, 1):
            print(f"{W}Step {i}:{RS} {step}")
    else:
        print(f"{D}No attack chain detected{RS}")


def print_verdict(threat: str, score: int) -> None:
    """Print the final threat verdict."""
    if threat == "CRITICAL":
        color = R
        symbol = "⚠"
    elif threat == "HIGH":
        color = Y
        symbol = "!"
    elif threat == "MEDIUM":
        color = Y
        symbol = "~"
    else:
        color = G
        symbol = "✓"

    verdict_str = f"{color}{symbol} {threat} THREAT (Score: {score}/100){RS}"
    
    print(f"  {verdict_str}")
    print()

    if threat in ["CRITICAL", "HIGH"]:
        print(f"  {R}[!] This PDF requires immediate attention{RS}")
    elif threat == "MEDIUM":
        print(f"  {Y}[!] This PDF warrants careful review{RS}")
    else:
        print(f"  {G}[✓] This PDF appears benign{RS}")


# ==========================================
# CONFIGURATION & API SETUP
# ==========================================

def setup_virustotal_key(config: Dict[str, Any]) -> str:
    """
    Get VirusTotal API key from config or prompt user to set it.
    Returns the API key or empty string if not available.
    """
    vt_key = config.get("virustotal_api_key", "")
    
    if not vt_key:
        print(f"\n{Y}[!] VirusTotal API key not configured{RS}")
        print(f"{Y}[!] Hash enrichment will be skipped for this run{RS}")
        response = input(f"\n{W}Enter VirusTotal API key (or press Enter to skip): {RS}").strip()
        
        if response:
            vt_key = response
            try:
                save_api_key("virustotal_api_key", vt_key)
                success("VirusTotal API key saved")
            except Exception as e:
                log.error(f"Failed to save VirusTotal key: {e}")
                warning(f"Failed to save key: {e}")
    
    return vt_key


# ==========================================
# MAIN ANALYSIS PIPELINE
# ==========================================

def main() -> None:
    """Main entry point for PDFUncover analysis."""

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="PDFUncover — comprehensive PDF malware analysis toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pdfuncover.py /path/to/suspicious.pdf
  pdfuncover.py -o /tmp/reports /path/to/file.pdf
  pdfuncover.py --no-correlation --formats json,html report.pdf
        """
    )

    parser.add_argument("pdf", help="Path to PDF file to analyze")
    parser.add_argument("-o", "--output", default="reports",
                        help="Output directory for reports (default: reports)")
    parser.add_argument("--formats", default="json,markdown,html,text",
                        help="Report formats (comma-separated: json,markdown,html,text)")
    parser.add_argument("--no-correlation", action="store_true",
                        help="Skip threat correlation engine")
    parser.add_argument("--no-attack-chain", action="store_true",
                        help="Skip attack chain reconstruction")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    # Show banner
    banner()

    # Validate PDF file
    pdf_path = args.pdf
    if not os.path.isfile(pdf_path):
        error(f"File not found: {pdf_path}")
        sys.exit(1)

    if not pdf_path.lower().endswith(".pdf"):
        warning(f"File does not have .pdf extension: {pdf_path}")

    # Load configuration
    try:
        config = load_config()
    except Exception as e:
        log.error(f"Failed to load config: {e}")
        config = {}

    # Create output directory
    reports_dir = args.output
    os.makedirs(reports_dir, exist_ok=True)
    status(f"Reports will be saved to: {reports_dir}")

    # ==========================================
    # METADATA EXTRACTION
    # ==========================================

    status("Extracting PDF metadata...")

    try:
        metadata = extract_metadata(pdf_path)
    except Exception as e:
        log.error(f"Metadata extraction failed: {e}")
        error(f"Metadata extraction failed: {e}")
        metadata = {}

    print_section("METADATA EXTRACTION")
    print_dictionary(metadata)

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
    #
    # HASH ENRICHMENT (Step 9): All hashes — from PDF text, extracted
    # embedded files, and now the metadata file itself — are extracted
    # as IOCs and enriched through the threat-intelligence pipeline.
    # No direct VirusTotal calls bypass the Engine anymore.

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