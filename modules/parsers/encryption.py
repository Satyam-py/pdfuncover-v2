# modules/parsers/encryption.py
#
# Encryption detection via qpdf.
#
# Moved verbatim from the "ENCRYPTION CHECK" section of the former
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


def analyze_encryption(pdf_path):
    """
    Detect whether the PDF is encrypted.

    Returns the same "Encryption" dict the original
    extract_embedded_objects() produced.
    """

    encryption_data = {
        "Encrypted": False
    }

    if shutil.which("qpdf"):

        encryption_output = run_command(
            ["qpdf", "--show-encryption", pdf_path]
        )

        encryption_data["Encrypted"] = (
            "R =" in encryption_output
            or "P =" in encryption_output
        )

    else:
        encryption_data["Error"] = "qpdf not installed"

    return encryption_data
