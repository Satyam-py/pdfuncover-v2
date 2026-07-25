# modules/parsers/streams.py
#
# Stream/object analysis: indirect object count, compressed-stream
# detection, per-stream entropy analysis, decompression, and shellcode
# pattern scanning of decompressed content.
#
# Redesign notes (analyze_streams() keeps its original name/signature
# and the "Streams" dict keeps its original keys — only the analysis
# behind them changed):
#   - Streams under MIN_STREAM_SIZE are skipped (raised from the
#     previous 16 bytes — too small a sample for entropy to mean
#     anything).
#   - Each stream's declared type is read from the object dictionary
#     text immediately preceding it (classify_stream_context), so
#     streams that declare themselves as images or embedded fonts are
#     skipped entirely — both are routinely high-entropy for
#     completely legitimate reasons, and were the single biggest
#     source of false positives in the old blanket entropy check.
#   - For streams that declare a generic compression filter, high
#     entropy in the *raw* bytes is expected and no longer flagged by
#     itself. What's actually checked is (a) whether the stream fails
#     to decompress despite declaring a filter — a known evasion/
#     malformation pattern — and (b) whether the *decompressed*
#     content is itself still high-entropy, which points to a second,
#     unaccounted-for layer of packing/encryption.
#   - Streams with no declared filter are held to the old raw-entropy
#     check, which is meaningful there: un-filtered PDF content
#     (operators, plain text) is not naturally high-entropy.
#   - Shellcode scanning now also runs on raw stream bytes when
#     decompression fails or wasn't applicable (previously skipped
#     entirely in that case, missing uncompressed shellcode), and
#     delegates to the corroborated-heuristics engine in helpers.py.

import os
import re
import shutil
import logging

from modules.parsers.helpers import (
    run_command,
    calculate_entropy,
    decompress_stream,
    detect_shellcode_patterns,
    classify_stream_context,
)


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
# CONFIGURATION
# ==========================================

# Streams smaller than this are too small a sample for entropy to be
# statistically meaningful (was 16 bytes — raised to cut noise).
MIN_STREAM_SIZE = 64

# How much of the object dictionary text immediately before a `stream`
# keyword to inspect when classifying its declared content type.
CONTEXT_WINDOW = 600

RAW_ENTROPY_THRESHOLD = 7.2
# A higher bar for a *second* layer of entropy inside content that
# already decompressed once — this is specifically about detecting
# packing/encryption nested inside an otherwise-normal compressed
# stream, so it's held to a stricter threshold than the raw check.
DECOMPRESSED_ENTROPY_THRESHOLD = 7.5


def analyze_streams(pdf_path, parser_output):
    """
    Analyze PDF streams: object count, compression presence, entropy,
    and shellcode indicators.

    `parser_output` is the plain `pdf-parser <pdf_path>` output computed
    once by the orchestrator (shared with the JavaScript/IOC parsers),
    passed in here so it isn't run twice.

    Returns the same "Streams" dict shape the original
    extract_embedded_objects() produced.
    """

    stream_data = {
        "Stream Objects Found": False,
        "Compressed Streams": False,
        "Object Count": 0,
        "High Entropy Streams": [],
        "Decompressed Findings": []
    }

    if shutil.which("pdf-parser"):

        # --stats gives clean "Indirect object: N" count
        stats_output = run_command(
            ["pdf-parser", "--stats", pdf_path]
        )

        obj_match = re.search(
            r"Indirect object:\s*(\d+)",
            stats_output
        )

        stream_data["Object Count"] = (
            int(obj_match.group(1)) if obj_match else 0
        )

        if "stream" in parser_output.lower():
            stream_data["Stream Objects Found"] = True

        if "/Filter" in parser_output:
            stream_data["Compressed Streams"] = True

        # Analyze entropy + decompress each stream
        try:

            with open(pdf_path, "rb") as f:
                raw_pdf = f.read()

            stream_pattern = re.compile(
                rb"stream\r?\n(.*?)\r?\nendstream",
                re.DOTALL
            )

            for i, match in enumerate(stream_pattern.finditer(raw_pdf)):

                stream_bytes = match.group(1)

                # Skip streams too small for entropy to mean anything
                if len(stream_bytes) < MIN_STREAM_SIZE:
                    continue

                context_start = max(0, match.start() - CONTEXT_WINDOW)
                context_window = raw_pdf[context_start:match.start()]

                # Trim to text after the nearest preceding endobj/endstream
                # boundary, if one falls inside the window — otherwise a
                # short object sitting close to a previous one can bleed
                # that object's /FontFile or /Image declaration into this
                # object's classification.
                last_boundary = max(
                    context_window.rfind(b"endobj"),
                    context_window.rfind(b"endstream"),
                )
                if last_boundary != -1:
                    context_window = context_window[last_boundary:]

                context_text = context_window.decode(
                    "latin-1", errors="replace"
                )
                stream_kind = classify_stream_context(context_text)

                # Normal images and embedded font programs are routinely
                # high-entropy (JPEG/DCT data, compressed font tables) —
                # that's expected, not suspicious. Skip both the entropy
                # and shellcode checks for them entirely.
                if stream_kind in ("image", "font"):
                    continue

                raw_entropy = calculate_entropy(stream_bytes)
                decompressed = decompress_stream(stream_bytes)

                decompressed_entropy = (
                    calculate_entropy(decompressed)
                    if decompressed is not None
                    else None
                )

                if stream_kind == "compressed":

                    if decompressed is None:
                        # Declares a filter but won't decompress —
                        # malformed stream or a known evasion technique.
                        stream_data["High Entropy Streams"].append(
                            f"Stream {i} — declares a compression filter "
                            f"but failed to decompress (entropy "
                            f"{raw_entropy}, size {len(stream_bytes)} "
                            f"bytes) — malformed stream or evasion attempt"
                        )

                    elif decompressed_entropy > DECOMPRESSED_ENTROPY_THRESHOLD:
                        # High entropy is expected in the raw compressed
                        # bytes; it's NOT expected to survive
                        # decompression. Still-high entropy afterward
                        # points to a second, unaccounted-for layer.
                        stream_data["High Entropy Streams"].append(
                            f"Stream {i} — decompresses to entropy "
                            f"{decompressed_entropy} despite declared "
                            f"compression (size: {len(decompressed)} "
                            f"bytes) — possible nested packed payload"
                        )

                else:
                    # No declared compression/image/font filter.
                    # Un-filtered PDF content (operators, plain text,
                    # glyph outlines) is not naturally high-entropy, so
                    # this remains a meaningful signal on its own.
                    if raw_entropy > RAW_ENTROPY_THRESHOLD:
                        stream_data["High Entropy Streams"].append(
                            f"Stream {i} — entropy {raw_entropy} "
                            f"(size: {len(stream_bytes)} bytes, no "
                            f"declared compression filter)"
                        )

                # Scan whichever form of the data is actual native
                # bytes — decompressed content if we got it, otherwise
                # the raw stream (scanning still-compressed bytes for
                # instruction-level patterns is meaningless, but
                # uncompressed shellcode shouldn't go unscanned just
                # because decompression wasn't applicable).
                scan_target = (
                    decompressed if decompressed is not None else stream_bytes
                )

                sc_findings = detect_shellcode_patterns(scan_target)

                for finding in sc_findings:
                    stream_data["Decompressed Findings"].append(
                        f"Stream {i}: {finding}"
                    )

        except OSError as e:
            log.error(f"Stream entropy analysis failed: {e}")

    else:
        stream_data["Error"] = "pdf-parser not installed"

    return stream_data