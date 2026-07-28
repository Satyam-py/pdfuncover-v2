# modules/parsers/acroform.py
#
# AcroForm / Additional-Action (/AA) / XFA detection.
#
# Moved verbatim from the "ACROFORM / AA DETECTION" section of the
# former extract_embedded_objects() — no logic changed.

import shutil

from modules.parsers.helpers import run_command
from modules.logging_config import get_logger

log = get_logger(__name__, "logs/embedded_extraction.log")


def analyze_acroform(pdf_path):
    """
    Detect /AcroForm, /AA (additional action), and /XFA presence,
    requiring an actual object reference rather than just a string
    mention.

    Returns the same "AcroForm" dict the original
    extract_embedded_objects() produced.
    """

    acroform_data = {
        "AcroForm Detected": False,
        "Additional Actions Found": False,
        "XFA Form Detected": False
    }

    if shutil.which("pdf-parser"):

        acroform_output = run_command(
            ["pdf-parser", "--search", "/AcroForm", pdf_path]
        )

        aa_output = run_command(
            ["pdf-parser", "--search", "/AA", pdf_path]
        )

        xfa_output = run_command(
            ["pdf-parser", "--search", "/XFA", pdf_path]
        )

        # Require an actual object reference — not just string mention
        # pdf-parser output contains "obj" when a real object is found
        if acroform_output.strip() and "obj" in acroform_output:
            acroform_data["AcroForm Detected"] = True

        # /AA must appear as a dictionary key in an object, not just content
        if aa_output.strip() and "obj" in aa_output:
            acroform_data["Additional Actions Found"] = True

        # XFA requires both the tag and an actual object
        if xfa_output.strip() and "obj" in xfa_output:
            acroform_data["XFA Form Detected"] = True

    return acroform_data