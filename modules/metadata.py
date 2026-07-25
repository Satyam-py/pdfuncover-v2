# modules/metadata.py

import subprocess
import hashlib
import os
import re
import shutil
import logging
from datetime import datetime


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/metadata.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


# ==========================================
# HELPERS
# ==========================================

def run_command(command, timeout=30):
    """
    Runs a shell command safely with timeout.
    Returns stdout or empty string on failure.
    Logs errors instead of silently swallowing them.
    """

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return result.stdout

    except subprocess.TimeoutExpired:

        log.error(f"Command timed out: {command}")
        return ""

    except FileNotFoundError:

        log.error(f"Command not found: {command[0]}")
        return ""

    except OSError as e:

        log.error(f"OS error running {command}: {e}")
        return ""


def calculate_hash(file_path):
    """
    Calculate MD5, SHA1, SHA256 hashes of a file.
    Reads in 4KB chunks to handle large files safely.
    """

    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:

        with open(file_path, "rb") as f:

            while chunk := f.read(4096):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "MD5":    md5.hexdigest(),
            "SHA1":   sha1.hexdigest(),
            "SHA256": sha256.hexdigest()
        }

    except OSError as e:

        log.error(f"Hashing failed for {file_path}: {e}")

        return {
            "MD5":    "Error",
            "SHA1":   "Error",
            "SHA256": "Error"
        }


def parse_output(output):
    """
    Converts colon-separated command output into a dictionary.
    Handles multi-colon values correctly (splits on first colon only).
    """

    data = {}

    for line in output.splitlines():

        if ":" in line:

            key, value = line.split(":", 1)

            key   = key.strip()
            value = value.strip()

            if key and value:
                data[key] = value

    return data


def parse_date(date_str):
    """
    Attempt to parse and normalize PDF date strings.
    PDF dates look like: D:20230415120000+05'30'
    Returns human-readable string or original if unparseable.
    """

    if not date_str:
        return date_str

    # Strip PDF D: prefix
    cleaned = re.sub(r"^D:", "", date_str.strip())

    # Try common formats
    formats = [
        "%Y%m%d%H%M%S",
        "%Y%m%d%H%M%S%z",
        "%Y%m%d",
    ]

    # Normalize timezone offset D:20230415120000+05'30' -> strip tz part
    cleaned = re.sub(r"[+\-Z]\d{2}'\d{2}'$", "", cleaned)
    cleaned = re.sub(r"[+\-Z]\d{4}$", "", cleaned)

    for fmt in formats:

        try:

            dt = datetime.strptime(cleaned[:len(fmt.replace("%", "XX").replace("X", ""))], fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")

        except ValueError:
            continue

    return date_str


def get_file_size_human(size_bytes):
    """
    Convert bytes to human-readable size string.
    """

    if size_bytes < 1024:
        return f"{size_bytes} bytes"

    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB ({size_bytes} bytes)"

    else:
        return f"{size_bytes / (1024*1024):.2f} MB ({size_bytes} bytes)"


def check_suspicious_metadata(metadata):
    """
    Run heuristic checks on extracted metadata.
    Returns a list of suspicious finding strings.
    """

    flags = []

    # JavaScript embedded
    if metadata.get("JavaScript", "").lower() == "yes":
        flags.append("Embedded JavaScript detected")

    # Encrypted
    if metadata.get("Encrypted", "").lower() == "yes":
        flags.append("Encrypted PDF")

    # Exiftool warnings
    if "Warning" in metadata:
        flags.append(f"Exiftool warning: {metadata['Warning']}")

    # Missing author
    if not metadata.get("Author"):
        flags.append("Missing Author metadata")

    # Missing creator
    if not metadata.get("Creator"):
        flags.append("Missing Creator metadata")

    # Mismatched creation/modification dates
    creation  = metadata.get("CreationDate", "")
    mod_date  = metadata.get("ModDate", "")

    if creation and mod_date and creation != mod_date:
        flags.append(
            "CreationDate and ModDate differ — "
            "document may have been modified after creation"
        )

    # Suspicious producer tools known to be used in malicious PDFs
    suspicious_producers = [
        "fpdf",
        "reportlab",
        "unknown",
        "none"
    ]

    producer = metadata.get("Producer", "").lower()

    if any(p in producer for p in suspicious_producers):
        flags.append(
            f"Suspicious producer tool: {metadata.get('Producer', '')}"
        )

    # Suspicious titles
    suspicious_title_keywords = [
        "invoice",
        "payment",
        "urgent",
        "refund",
        "verify",
        "confirm",
        "suspended",
        "winner",
        "prize"
    ]

    title = metadata.get("Title", "").lower()

    if any(kw in title for kw in suspicious_title_keywords):
        flags.append(
            f"Suspicious title keyword detected: {metadata.get('Title', '')}"
        )

    # Very large file — could indicate embedded payload
    raw_size = metadata.get("_raw_size", 0)

    if isinstance(raw_size, int) and raw_size > 5 * 1024 * 1024:
        flags.append(
            f"Large file size ({get_file_size_human(raw_size)}) "
            "— may contain embedded payload"
        )

    # Zero pages
    pages = metadata.get("Pages", "")

    try:
        if int(pages) == 0:
            flags.append("PDF reports 0 pages — malformed or evasion attempt")
    except (ValueError, TypeError):
        pass

    return flags


# ==========================================
# MAIN EXTRACTOR
# ==========================================

def extract_metadata(pdf_path):
    """
    Extract and analyze metadata from a PDF file.
    Returns structured metadata dictionary with suspicious flags.
    """

    metadata = {}

    # ==========================================
    # BASIC FILE INFO
    # ==========================================

    try:

        raw_size = os.path.getsize(pdf_path)

        metadata["File Name"] = os.path.basename(pdf_path)
        metadata["File Path"] = os.path.abspath(pdf_path)
        metadata["File Size"] = get_file_size_human(raw_size)
        metadata["_raw_size"] = raw_size  # used internally for checks

    except OSError as e:

        log.error(f"Could not stat file {pdf_path}: {e}")
        metadata["File Name"] = os.path.basename(pdf_path)
        metadata["File Size"] = "Unknown"
        metadata["_raw_size"] = 0

    # ==========================================
    # HASHES
    # ==========================================

    hashes = calculate_hash(pdf_path)
    metadata.update(hashes)

    # ==========================================
    # PDFINFO
    # ==========================================

    if shutil.which("pdfinfo"):

        pdfinfo_output = run_command(["pdfinfo", pdf_path])
        pdfinfo_data   = parse_output(pdfinfo_output)

        important_fields = [
            "Title",
            "Subject",
            "Author",
            "Creator",
            "Producer",
            "CreationDate",
            "ModDate",
            "Pages",
            "Encrypted",
            "JavaScript",
            "PDF version",
            "Tagged",
            "Optimized",
            "Page size",
            "File size"
        ]

        for field in important_fields:

            if field in pdfinfo_data:

                value = pdfinfo_data[field]

                # Normalize date fields
                if field in ("CreationDate", "ModDate"):
                    value = parse_date(value)

                metadata[field] = value

    else:

        metadata["pdfinfo"] = "Not installed"

    # ==========================================
    # EXIFTOOL
    # ==========================================

    if shutil.which("exiftool"):

        exif_output = run_command(["exiftool", pdf_path])
        exif_data   = parse_output(exif_output)

        important_exif_fields = [
            "File Type",
            "MIME Type",
            "PDF Version",
            "Linearized",
            "Warning",
            "XMP Toolkit",
            "Format",
            "Description",
            "Rights"
        ]

        for field in important_exif_fields:

            if field in exif_data:
                metadata[field] = exif_data[field]

    else:

        metadata["exiftool"] = "Not installed"

    # ==========================================
    # SUSPICIOUS CHECKS
    # ==========================================

    suspicious_flags = check_suspicious_metadata(metadata)

    # Remove internal key before returning
    metadata.pop("_raw_size", None)

    metadata["Suspicious Flags"] = suspicious_flags

    return metadata