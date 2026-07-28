# modules/parsers/flags.py
#
# Aggregates the per-category result dicts into the flat human-readable
# "Suspicious Flags" string list.
#
# Moved verbatim from the "SUSPICIOUS FLAGS" section of the former
# extract_embedded_objects() — no logic changed.

from modules.logging_config import get_logger

log = get_logger(__name__, "logs/embedded_extraction.log")


def build_suspicious_flags(
    header_data, js_data, embedded_data, stream_data,
    compression_data, encryption_data, ioc_data, acroform_data
):
    """
    Build the flat "Suspicious Flags" string list from the already
    computed per-category result dicts.
    """

    suspicious_flags = []

    if not header_data["Valid PDF Header"]:
        suspicious_flags.append("Invalid PDF header — possible spoofed file")

    if js_data["JavaScript Detected"]:
        suspicious_flags.append("Embedded JavaScript detected")

    if js_data["OpenAction Found"]:
        suspicious_flags.append("OpenAction trigger found")

    if js_data["Suspicious Keywords"]:
        suspicious_flags.append(
            f"Suspicious JS keywords: {', '.join(js_data['Suspicious Keywords'])}"
        )

    if embedded_data["Embedded Files Found"]:
        suspicious_flags.append("Embedded files detected")

    if embedded_data["Suspicious Files"]:
        for sf in embedded_data["Suspicious Files"]:
            suspicious_flags.append(f"Dangerous embedded file: {sf}")

    if stream_data["High Entropy Streams"]:
        suspicious_flags.append(
            f"{len(stream_data['High Entropy Streams'])} high-entropy "
            f"stream(s) detected — possible encrypted payload"
        )

    if stream_data["Decompressed Findings"]:
        for finding in stream_data["Decompressed Findings"]:
            suspicious_flags.append(f"Shellcode pattern: {finding}")

    if compression_data["Compressed Objects Found"]:
        suspicious_flags.append("Compressed objects present")

    if compression_data.get("JBIG2 Warning"):
        suspicious_flags.append(compression_data["JBIG2 Warning"])

    if encryption_data["Encrypted"]:
        suspicious_flags.append("Encrypted PDF")

    if ioc_data["URLs"]:
        suspicious_flags.append(
            f"{len(ioc_data['URLs'])} URL(s) found inside PDF"
        )

    if ioc_data["IPs"]:
        suspicious_flags.append(
            f"{len(ioc_data['IPs'])} IP address(es) found inside PDF"
        )

    if acroform_data["AcroForm Detected"]:
        suspicious_flags.append("AcroForm detected — possible data exfiltration")

    if acroform_data["Additional Actions Found"]:
        suspicious_flags.append("/AA trigger found — action on page open/close")

    if acroform_data["XFA Form Detected"]:
        suspicious_flags.append("XFA form detected — used in exploit delivery")

    return suspicious_flags