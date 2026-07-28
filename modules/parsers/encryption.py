# modules/parsers/encryption.py
#
# Encryption detection via qpdf.
#
# Moved verbatim from the "ENCRYPTION CHECK" section of the former
# extract_embedded_objects() — no logic changed.

import shutil

from modules.parsers.helpers import run_command
from modules.logging_config import get_logger

log = get_logger(__name__, "logs/embedded_extraction.log")


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