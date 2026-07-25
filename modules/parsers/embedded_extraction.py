# modules/embedded_extraction.py
#
# Orchestrator. This file used to contain all parsing/detection logic
# directly; that logic has been split into modules/parsers/ (one file
# per responsibility). This file now only wires the parser functions
# together in the same order as before and assembles the identical
# `results` dict.
#
# Public API is unchanged for backward compatibility:
#   - extract_embedded_objects(pdf_path)
#   - make_evidence, SEVERITY_*, CONFIDENCE_* (re-exported for
#     modules/analyzer.py, which imports them from this module)

import os
import shutil
import logging

from modules.parsers.helpers import run_command
from modules.parsers.evidence import (
    make_evidence,
    build_evidence,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    EXPLOIT_API_KEYWORDS,
    STANDARD_COMPRESSION_FILTERS,
)
from modules.parsers.header import analyze_header
from modules.parsers.streams import analyze_streams
from modules.parsers.javascript import analyze_javascript
from modules.parsers.iocs import extract_iocs
from modules.parsers.embedded import extract_embedded_files
from modules.parsers.images import extract_images
from modules.parsers.compression import analyze_compression
from modules.parsers.encryption import analyze_encryption
from modules.parsers.acroform import analyze_acroform
from modules.parsers.flags import build_suspicious_flags


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
# MAIN ANALYZER
# ==========================================

def extract_embedded_objects(pdf_path):
    """
    Full embedded object analysis of a PDF file.
    Returns a structured results dictionary.

    Behavior is identical to the original monolithic implementation —
    only the internal organization changed. Each section below is now
    a call into modules/parsers/<name>.py instead of inline code.
    """

    results = {}

    # ==========================================
    # PDF HEADER VALIDATION
    # ==========================================

    header_data = analyze_header(pdf_path)
    results["Header Validation"] = header_data

    # ==========================================
    # COMMON OUTPUTS
    # ==========================================
    # Computed once here and shared across the parsers that need them
    # (Streams, JavaScript, IOCs) — exactly as in the original file.

    strings_output = run_command(["strings", pdf_path])

    parser_output = ""

    if shutil.which("pdf-parser"):
        parser_output = run_command(["pdf-parser", pdf_path])

    # ==========================================
    # STREAM ANALYSIS
    # ==========================================

    stream_data = analyze_streams(pdf_path, parser_output)
    results["Streams"] = stream_data

    # ==========================================
    # JAVASCRIPT DETECTION
    # ==========================================

    js_data = analyze_javascript(pdf_path, strings_output)
    results["JavaScript"] = js_data

    # ==========================================
    # IOC EXTRACTION
    # ==========================================

    ioc_data = extract_iocs(pdf_path, strings_output)
    results["IOCs"] = ioc_data

    # ==========================================
    # EMBEDDED FILES
    # ==========================================

    embedded_data = extract_embedded_files(pdf_path)
    results["Embedded Files"] = embedded_data

    # ==========================================
    # IMAGE EXTRACTION
    # ==========================================

    image_data = extract_images(pdf_path)
    results["Images"] = image_data

    # ==========================================
    # COMPRESSION CHECK
    # ==========================================

    compression_data = analyze_compression(pdf_path)
    results["Compression"] = compression_data

    # ==========================================
    # ENCRYPTION CHECK
    # ==========================================

    encryption_data = analyze_encryption(pdf_path)
    results["Encryption"] = encryption_data

    # ==========================================
    # ACROFORM / AA DETECTION
    # ==========================================

    acroform_data = analyze_acroform(pdf_path)
    results["AcroForm"] = acroform_data

    # ==========================================
    # SUSPICIOUS FLAGS
    # ==========================================

    suspicious_flags = build_suspicious_flags(
        header_data, js_data, embedded_data, stream_data,
        compression_data, encryption_data, ioc_data, acroform_data
    )
    results["Suspicious Flags"] = suspicious_flags

    # ==========================================
    # EVIDENCE (additive — does not replace any existing key)
    # ==========================================
    #
    # Re-represents everything already detected above as standardized
    # Evidence objects. analyzer.py consumes this to correlate findings
    # across categories. All original keys remain unchanged for
    # backward compatibility with existing CLI/reporting code.

    results["Evidence"] = build_evidence(
        header_data, stream_data, js_data, ioc_data,
        embedded_data, compression_data, encryption_data, acroform_data
    )

    return results
