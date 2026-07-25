# modules/parsers/header.py
#
# PDF header validation (the "PDF HEADER VALIDATION" section of the
# former extract_embedded_objects()). Moved verbatim — no logic changed.

import os
import logging

from modules.parsers.helpers import validate_pdf_header


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


def analyze_header(pdf_path):
    """
    Validate the PDF's magic-byte header.
    Returns the same "Header Validation" dict the original
    extract_embedded_objects() produced.
    """

    header_data = {
        "Valid PDF Header": False,
        "Header Warning": ""
    }

    if validate_pdf_header(pdf_path):

        header_data["Valid PDF Header"] = True

    else:

        header_data["Valid PDF Header"] = False
        header_data["Header Warning"] = (
            "File does not start with %PDF- — "
            "may be spoofed or corrupted"
        )

    return header_data
