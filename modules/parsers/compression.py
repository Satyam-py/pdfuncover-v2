# modules/parsers/compression.py
#
# Compression filter detection (including the JBIG2Decode /
# CVE-2010-0188 check).
#
# Moved verbatim from the "COMPRESSION CHECK" section of the former
# extract_embedded_objects() — no logic changed.

import os
import shutil
import logging

from modules.parsers.helpers import run_command


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


def analyze_compression(pdf_path):
    """
    Detect compression filters present in the PDF's objects.

    Returns the same "Compression" dict the original
    extract_embedded_objects() produced.
    """

    compression_data = {
        "Compressed Objects Found": False,
        "Filters": []
    }

    if shutil.which("pdf-parser"):

        filter_output = run_command(
            ["pdf-parser", "--search", "/Filter", pdf_path]
        )

        compression_filters = [
            "FlateDecode",
            "ASCIIHexDecode",
            "ASCII85Decode",
            "LZWDecode",
            "RunLengthDecode",
            "JBIG2Decode",     # used in CVE-2010-0188
            "CCITTFaxDecode",
            "DCTDecode"
        ]

        found_filters = [
            f for f in compression_filters
            if f in filter_output
        ]

        compression_data["Compressed Objects Found"] = bool(found_filters)
        compression_data["Filters"] = found_filters

        # JBIG2Decode is a known exploit vector — flag it
        if "JBIG2Decode" in found_filters:
            compression_data["JBIG2 Warning"] = (
                "JBIG2Decode detected — associated with CVE-2010-0188"
            )

    else:
        compression_data["Error"] = "pdf-parser not installed"

    return compression_data
