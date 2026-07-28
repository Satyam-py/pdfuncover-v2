# modules/parsers/embedded.py
#
# Embedded file extraction using two strategies: pdf-parser object
# dumps (Strategy 1) and raw byte-stream regex extraction for inline
# embedded files with no separate object number (Strategy 2).
#
# REDESIGN NOTES (final implementation):
#
#   - "Embedded Files Found" / "Extracted To" contradiction removed:
#     both are now derived from the same single source of truth
#     (len(extracted_files) > 0) at the very end, instead of being set
#     independently at multiple points during the two strategies.
#
#   - Strategy 1 no longer treats /Filespec dictionary objects (the
#     metadata describing an attachment — filename, description, an
#     /EF reference) as if they were the embedded file's own content.
#     It now resolves the /EF /F N 0 R indirect reference to dump the
#     actual /Type /EmbeddedFile stream object, and correlates that
#     dump with the real filename pulled from its Filespec. Previously
#     the Filespec object itself was blindly --raw dumped and reported
#     as an "extracted file", which produced a PDF dictionary snippet
#     masquerading as file content — a direct source of false
#     positives.
#
#   - Strategy 2 now splits the raw PDF into "N G obj ... endobj"
#     blocks *before* matching /F / /EmbeddedFile / stream markers,
#     instead of running one unbounded ".*?" regex over the entire
#     file. The old approach could pair a filename from one object
#     with a stream belonging to a different, later object simply
#     because both patterns eventually matched somewhere downstream
#     in the same file — a correctness bug, and a performance/
#     backtracking risk on large files. A bounded-window fallback
#     still catches embedded files that aren't wrapped in a literal
#     "obj"/"endobj" pair (e.g. hand-crafted or lightly obfuscated
#     PDFs), matching the strategy's original intent.
#
#   - Filenames (both strategies) are now parsed with a proper
#     balanced-parens / escape-aware scanner (find_balanced_parens_content
#     / find_balanced_parens_bytes) instead of a naive "[^)]+" match,
#     so filenames containing escaped or nested parentheses no longer
#     get truncated or misparsed.
#
#   - "Suspicious Files" is now backed by real content inspection, not
#     just a filename-extension check: magic-byte-vs-extension
#     mismatch (e.g. an MZ-header binary saved with a .txt extension),
#     Shannon entropy, and the existing shellcode heuristics in
#     helpers.py all feed into it, alongside the original dangerous-
#     extension check.
#
#   - Filenames are sanitized (control characters, path traversal,
#     length) and collisions on disk are resolved with a numeric
#     suffix instead of silently overwriting or silently skipping.
#
#   - Every per-object / per-match step is wrapped so one bad object
#     can't abort extraction of the rest, with failures logged with
#     context instead of silently swallowed.

import os
import re
import shutil

from modules.parsers.helpers import (
    run_command,
    is_suspicious_filename,
    calculate_entropy,
    detect_shellcode_patterns,
    find_balanced_parens_content,
    find_balanced_parens_bytes,
)

from modules.logging_config import get_logger


# ==========================================
# PDF STRING-LITERAL UNESCAPING
# ==========================================
#
# helpers.decode_octal_bytes() / decode_pdf_string() only resolve
# octal escapes (\NNN). They leave the standard single-character PDF
# string escapes — \n \r \t \b \f \( \) \\ — and line-continuation
# escapes (backslash immediately followed by a newline) untouched.
# For filenames specifically that's a real bug, not a cosmetic one:
# a name like "weird\(name\).txt" would keep its literal backslashes,
# which then get misread as path separators by the filename
# sanitizer downstream and truncate the name. These do a full PDF
# string-literal unescape instead, scoped to embedded-file filename
# handling.

_ESCAPE_MAP_BYTES = {
    b"n": b"\n", b"r": b"\r", b"t": b"\t",
    b"b": b"\x08", b"f": b"\x0c",
    b"(": b"(", b")": b")", b"\\": b"\\",
}

_ESCAPE_MAP_STR = {
    "n": "\n", "r": "\r", "t": "\t",
    "b": "\x08", "f": "\x0c",
    "(": "(", ")": ")", "\\": "\\",
}


def _unescape_pdf_bytes(data):
    """Fully unescape a raw PDF string-literal payload (bytes)."""

    out = bytearray()
    i = 0
    length = len(data)

    while i < length:
        b = data[i:i + 1]

        if b != b"\\" or i + 1 >= length:
            out += b
            i += 1
            continue

        nxt = data[i + 1:i + 2]

        if nxt in (b"\r", b"\n"):
            i += 2
            if nxt == b"\r" and data[i:i + 1] == b"\n":
                i += 1
            continue

        if nxt in b"01234567":
            octal = data[i + 1:i + 4]
            digits = bytearray()
            for c in octal:
                if bytes([c]) in b"01234567":
                    digits.append(c)
                else:
                    break
            if digits:
                out.append(int(bytes(digits), 8) & 0xFF)
                i += 1 + len(digits)
                continue

        if nxt in _ESCAPE_MAP_BYTES:
            out += _ESCAPE_MAP_BYTES[nxt]
            i += 2
            continue

        # Unknown escape — PDF spec: drop the backslash, keep the char.
        out += nxt
        i += 2

    return out.decode(errors="replace")


def _unescape_pdf_str(text):
    """Fully unescape a PDF string-literal payload (str)."""

    out = []
    i = 0
    length = len(text)

    while i < length:
        ch = text[i]

        if ch != "\\" or i + 1 >= length:
            out.append(ch)
            i += 1
            continue

        nxt = text[i + 1]

        if nxt in ("\r", "\n"):
            i += 2
            if nxt == "\r" and i < length and text[i] == "\n":
                i += 1
            continue

        if nxt in "01234567":
            digits = ""
            for c in text[i + 1:i + 4]:
                if c in "01234567":
                    digits += c
                else:
                    break
            if digits:
                out.append(chr(int(digits, 8) & 0xFF))
                i += 1 + len(digits)
                continue

        if nxt in _ESCAPE_MAP_STR:
            out.append(_ESCAPE_MAP_STR[nxt])
            i += 2
            continue

        out.append(nxt)
        i += 2

    return "".join(out)


log = get_logger(__name__, "logs/embedded_extraction.log")


# ==========================================
# FILENAME / PATH HANDLING
# ==========================================

def _sanitize_filename(raw_name, fallback):
    """
    Turn an arbitrary, possibly hostile filename string pulled out of
    a PDF into something safe to use as a path component: no
    directory traversal, no control characters, no reserved
    characters, bounded length. Falls back to `fallback` if nothing
    usable survives.
    """

    name = (raw_name or "").strip().strip("\x00")
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r'[\x00-\x1f\\/:*?"<>|]', "_", name)
    name = name.strip(" .")

    if not name:
        name = fallback

    return name[:200]


def _unique_path(directory, filename):
    """
    Resolve a save path that won't collide with a file already on
    disk from this run, appending a numeric suffix rather than
    silently overwriting a different embedded object that happens to
    share a filename.
    """

    candidate = os.path.join(directory, filename)

    if not os.path.exists(candidate):
        return candidate

    base, ext = os.path.splitext(filename)
    i = 1

    while True:
        candidate = os.path.join(directory, f"{base}_{i}{ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1


# ==========================================
# DANGEROUS CONTENT DETECTION
# ==========================================
#
# Extension checks alone are trivially defeated by renaming a file.
# These look at what the bytes actually are.

_MAGIC_SIGNATURES = {
    ".exe": (b"MZ",),
    ".dll": (b"MZ",),
    ".scr": (b"MZ",),
    ".cpl": (b"MZ",),
    ".com": (b"MZ",),
    ".jar": (b"PK\x03\x04",),
    ".zip": (b"PK\x03\x04",),
}

_ENTROPY_SUSPICIOUS_THRESHOLD = 7.2


def _detect_dangerous_content(fname, data):
    """
    Inspect actual file bytes (not just the filename) for indicators
    worth flagging. Returns a list of human-readable reason strings —
    empty if nothing stood out.
    """

    reasons = []
    ext = os.path.splitext(fname.lower())[1]

    if is_suspicious_filename(fname):
        reasons.append("dangerous file extension")

    sigs = _MAGIC_SIGNATURES.get(ext)
    if sigs and not any(data.startswith(sig) for sig in sigs):
        reasons.append(
            f"extension '{ext}' does not match file content "
            f"(possible masquerade)"
        )

    if data.startswith(b"MZ") and ext not in (
        ".exe", ".dll", ".scr", ".cpl", ".com"
    ):
        reasons.append(
            "Windows executable (MZ header) saved with a "
            "non-executable extension"
        )

    if len(data) >= 64:
        entropy = calculate_entropy(data[:8192])
        if entropy >= _ENTROPY_SUSPICIOUS_THRESHOLD:
            reasons.append(
                f"high entropy ({entropy}/8) — possibly packed, "
                f"encrypted, or otherwise obfuscated payload"
            )

    reasons.extend(detect_shellcode_patterns(data))

    return reasons


# ==========================================
# STRATEGY 1 HELPERS: pdf-parser object correlation
# ==========================================

_OBJ_HEADER_RE = re.compile(r"(\d+)\s+(\d+)\s+obj\b")
_EF_REF_RE = re.compile(r"/EF\s*<<.*?/F\s+(\d+)\s+\d+\s+R", re.DOTALL)


def _split_object_blocks(search_output):
    """
    Split a pdf-parser --search output blob into per-object blocks
    keyed by object number. pdf-parser prints the full body of every
    matching object, so this recovers which object number each
    dictionary/stream actually belongs to, instead of treating the
    entire output as one undifferentiated blob (which previously let
    unrelated object numbers leak into "Embedded Objects").
    """

    blocks = {}

    if not search_output:
        return blocks

    matches = list(_OBJ_HEADER_RE.finditer(search_output))

    for i, m in enumerate(matches):
        obj_num = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(search_output)
        blocks[obj_num] = {
            "header": f"{obj_num} {m.group(2)} obj",
            "text": search_output[start:end],
        }

    return blocks


def _extract_filespec_filename(text):
    """
    Pull the real filename out of a /Filespec object's dictionary text
    (prefers /UF — the unicode form — falling back to /F), using a
    balanced-parens scan so escaped/nested parens don't truncate it.
    """

    for key in ("/UF", "/F"):
        idx = text.find(key)
        while idx != -1:
            paren_idx = text.find("(", idx)
            if paren_idx != -1 and paren_idx - idx <= 10:
                content = find_balanced_parens_content(text, paren_idx)
                if content:
                    return _unescape_pdf_str(content)
            idx = text.find(key, idx + 1)

    return None


def _extract_ef_reference(text):
    """
    Pull the object number the Filespec's /EF /F points at — the
    actual EmbeddedFile stream object carrying the file's bytes.
    """

    m = _EF_REF_RE.search(text)
    return m.group(1) if m else None


# ==========================================
# STRATEGY 2 HELPERS: bounded raw byte-stream extraction
# ==========================================

_OBJ_BYTES_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)endobj", re.DOTALL)
_STREAM_RE = re.compile(
    rb"/EmbeddedFile.{0,4096}?stream\r?\n(.*?)\r?\nendstream", re.DOTALL
)
_MAX_FALLBACK_CONTEXT = 4096


def _find_embedded_filename_bytes(chunk):
    """
    Locate a /UF(...) or /F(...) filename inside a raw byte chunk,
    using a balanced-parens scan (handles escaped/nested parens
    correctly, unlike a plain "[^)]+" match).
    """

    for key in (b"/UF", b"/F"):
        idx = chunk.find(key)
        while idx != -1:
            paren_idx = chunk.find(b"(", idx)
            if paren_idx != -1 and paren_idx - idx <= 10:
                content = find_balanced_parens_bytes(chunk, paren_idx)
                if content is not None:
                    return _unescape_pdf_bytes(content)
            idx = chunk.find(key, idx + 1)

    return None


def _iter_embedded_streams(raw_pdf):
    """
    Yield (filename, stream_bytes) pairs found by scanning the raw PDF
    bytes.

    Primary pass: split into literal "N G obj ... endobj" blocks and
    only look for /EmbeddedFile + stream markers *within* a single
    block, so a filename can never get paired with an unrelated
    object's stream.

    Fallback pass: for /EmbeddedFile+stream markers not inside any
    recognized obj/endobj wrapper (malformed or hand-crafted PDFs),
    search a bounded window immediately preceding the match for a
    filename instead of scanning the whole file unbounded.
    """

    covered = []

    for obj_match in _OBJ_BYTES_RE.finditer(raw_pdf):
        body = obj_match.group(3)

        if b"/EmbeddedFile" not in body or b"stream" not in body:
            continue

        stream_match = _STREAM_RE.search(body)
        if not stream_match:
            continue

        covered.append((obj_match.start(), obj_match.end()))

        fname = _find_embedded_filename_bytes(body) or "object_stream.bin"
        yield fname, stream_match.group(1)

    for stream_match in _STREAM_RE.finditer(raw_pdf):
        start, end = stream_match.start(), stream_match.end()

        if any(c_start <= start and end <= c_end for c_start, c_end in covered):
            continue  # already handled by the object-bounded pass above

        context_start = max(0, start - _MAX_FALLBACK_CONTEXT)
        context = raw_pdf[context_start:start]

        fname = _find_embedded_filename_bytes(context) or "embedded_file.bin"
        yield fname, stream_match.group(1)


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def extract_embedded_files(pdf_path):
    """
    Extract embedded files from the PDF using both the object-dump
    strategy and the raw byte-stream strategy.

    Returns the same "Embedded Files" dict shape the original
    extract_embedded_objects() produced:
        {
            "Embedded Files Found": bool,
            "Embedded Objects": [str, ...],
            "Extracted Files": [str, ...],
            "Suspicious Files": [str, ...],
            "Extracted To": str,
        }
    plus the same optional "Error" / "Stream Extraction Error" keys
    the original used when a strategy couldn't run.
    """

    embedded_data = {
        "Embedded Files Found": False,
        "Embedded Objects": [],
        "Extracted Files": [],
        "Suspicious Files": [],
        "Extracted To": "None",
    }

    embedded_output_dir = "output/embedded"
    os.makedirs(embedded_output_dir, exist_ok=True)
    extracted_files = []

    # ------------------------------------------
    # STRATEGY 1: pdf-parser object dump, Filespec-correlated
    # ------------------------------------------

    if shutil.which("pdf-parser"):

        try:
            embedded_output = run_command(
                ["pdf-parser", "--search", "EmbeddedFile", pdf_path]
            )
            filespec_output = run_command(
                ["pdf-parser", "--search", "Filespec", pdf_path]
            )
        except Exception as e:
            log.error(f"pdf-parser search failed: {e}")
            embedded_output = ""
            filespec_output = ""

        embedded_blocks = _split_object_blocks(embedded_output)
        filespec_blocks = _split_object_blocks(filespec_output)

        object_blocks = dict(embedded_blocks)
        filename_map = {}
        target_obj_nums = set(embedded_blocks.keys())

        for obj_num, block in filespec_blocks.items():
            object_blocks.setdefault(obj_num, block)

            fname = _extract_filespec_filename(block["text"])
            ref_obj = _extract_ef_reference(block["text"])

            if ref_obj:
                target_obj_nums.add(ref_obj)
                if fname:
                    filename_map[ref_obj] = fname
            elif fname:
                # No resolvable /EF reference — fall back to treating
                # this object itself as the target.
                target_obj_nums.add(obj_num)
                filename_map.setdefault(obj_num, fname)

        for obj_num in target_obj_nums:

            try:
                dump_fname = _sanitize_filename(
                    filename_map.get(obj_num), f"object_{obj_num}.bin"
                )
                dump_path = _unique_path(embedded_output_dir, dump_fname)

                run_command([
                    "pdf-parser",
                    "--object", obj_num,
                    "--raw",
                    "--dump", dump_path,
                    pdf_path
                ])

                if not os.path.exists(dump_path):
                    continue

                if os.path.getsize(dump_path) == 0:
                    os.remove(dump_path)
                    continue

                with open(dump_path, "rb") as f:
                    content = f.read()

                extracted_files.append(dump_path)
                embedded_data["Embedded Objects"].append(
                    object_blocks.get(obj_num, {}).get(
                        "header", f"{obj_num} 0 obj"
                    )
                )

                for reason in _detect_dangerous_content(dump_fname, content):
                    embedded_data["Suspicious Files"].append(
                        f"{dump_fname} — {reason}"
                    )

            except OSError as e:
                log.error(
                    f"Strategy 1: failed to dump/validate object "
                    f"{obj_num}: {e}"
                )
            except Exception as e:
                log.error(
                    f"Strategy 1: unexpected error processing object "
                    f"{obj_num}: {e}"
                )

    else:
        embedded_data["Error"] = "pdf-parser not installed"

    # ------------------------------------------
    # STRATEGY 2: bounded raw byte-stream extraction
    # Works for inline embedded files with no separate object number,
    # or as a fallback when pdf-parser isn't available.
    # ------------------------------------------

    raw_pdf = None

    try:
        with open(pdf_path, "rb") as f:
            raw_pdf = f.read()
    except OSError as e:
        log.error(f"Strategy 2: could not read PDF file: {e}")
        embedded_data["Stream Extraction Error"] = str(e)

    if raw_pdf is not None:

        try:
            for raw_fname, stream_content in _iter_embedded_streams(raw_pdf):

                try:
                    fname = _sanitize_filename(raw_fname, "embedded_file.bin")
                    save_path = _unique_path(embedded_output_dir, fname)

                    with open(save_path, "wb") as out:
                        out.write(stream_content)

                    if os.path.getsize(save_path) == 0:
                        os.remove(save_path)
                        continue

                    extracted_files.append(save_path)

                    for reason in _detect_dangerous_content(fname, stream_content):
                        embedded_data["Suspicious Files"].append(
                            f"{fname} — {reason}"
                        )

                except OSError as e:
                    log.error(
                        f"Strategy 2: failed to write embedded file "
                        f"{raw_fname}: {e}"
                    )

        except Exception as e:
            log.error(f"Strategy 2 raw extraction failed: {e}")
            embedded_data["Stream Extraction Error"] = str(e)

    # ------------------------------------------
    # FINALIZE — single source of truth for Found / Extracted To,
    # so these two fields can no longer contradict each other.
    # ------------------------------------------

    deduped_objects = []
    seen_objects = set()
    for header in embedded_data["Embedded Objects"]:
        if header not in seen_objects:
            seen_objects.add(header)
            deduped_objects.append(header)

    deduped_suspicious = []
    seen_suspicious = set()
    for entry in embedded_data["Suspicious Files"]:
        if entry not in seen_suspicious:
            seen_suspicious.add(entry)
            deduped_suspicious.append(entry)

    embedded_data["Embedded Objects"] = deduped_objects
    embedded_data["Suspicious Files"] = deduped_suspicious
    embedded_data["Extracted Files"] = extracted_files
    embedded_data["Embedded Files Found"] = bool(extracted_files)
    embedded_data["Extracted To"] = (
        embedded_output_dir if extracted_files else "None"
    )

    return embedded_data