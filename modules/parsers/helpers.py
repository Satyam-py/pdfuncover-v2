# modules/parsers/helpers.py
#
# Generic, low-level helper utilities shared across the parser modules:
# shell execution, PDF string/byte decoding, entropy calculation,
# stream decompression, header validation, stream context
# classification, and shellcode heuristics.
#
# Redesign notes: decompress_stream() and detect_shellcode_patterns()
# keep their original names/signatures (called the same way by
# modules/parsers/streams.py) but their internals have been rewritten:
#   - decompress_stream() now also unwinds a leading ASCII85/ASCIIHex
#     pre-filter before a second zlib attempt, catching the common
#     [/ASCII85Decode /FlateDecode] chain the old version missed.
#   - detect_shellcode_patterns() no longer matches isolated static
#     byte signatures (trivially defeated, prone to false positives on
#     ordinary binary/compressed content). It now looks for structural,
#     corroborated indicators — NOP-sled run length, the GetPC
#     call/pop (or FPU) idiom, and x86 opcode-byte density — and only
#     reports a finding once independent signals agree, or one signal
#     is strong enough to stand alone.
# A new classify_stream_context() helper was added so callers can
# recognize streams that declare themselves as images or embedded
# fonts, which are routinely high-entropy for entirely legitimate
# reasons.
#
# All other functions are unchanged from the original
# modules/embedded_extraction.py.

import subprocess
import re
import math
import zlib
import base64

from collections import Counter
from modules.logging_config import get_logger

log = get_logger(__name__, "logs/embedded_extraction.log")


# ==========================================
# HELPERS
# ==========================================

def run_command(command, timeout=30):
    """
    Runs a shell command safely with timeout.
    Returns stdout+stderr or empty string on failure.
    Logs errors instead of silently swallowing them.
    """

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:

        log.error(f"Command timed out: {command}")
        return ""

    except FileNotFoundError:

        log.error(f"Command not found: {command[0]}")
        return ""

    except OSError as e:

        log.error(f"OS error running {command}: {e}")
        return ""


def decode_pdf_string(text):
    """
    Decode PDF string escapes relevant to text/IOC extraction:

      - Octal escapes: \\072 -> :   \\057 -> /   \\056 -> .
      - Line-continuation escapes: inside a PDF string literal, a
        backslash immediately followed by a newline means "no
        character here" — it's how long strings (long URLs among
        them) get wrapped across multiple lines in the file. Left
        alone, that split lands as literal backslash+newline noise in
        the middle of what should be one contiguous token (e.g. a URL
        gets torn in half at the wrap point). This collapses it away
        before the octal pass runs.
    """

    text = re.sub(r"\\\r?\n", "", text)

    return re.sub(
        r"\\([0-7]{3})",
        lambda x: chr(int(x.group(1), 8)),
        text
    )


def decode_octal_bytes(b):
    """
    Decode octal escapes in raw bytes and return a string.
    Example: b'secret\\056txt' -> 'secret.txt'
    """

    return re.sub(
        rb"\\([0-7]{3})",
        lambda m: bytes([int(m.group(1), 8)]),
        b
    ).decode(errors="replace")


def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte string.
    Score 0-8. Above 7.2 = likely encrypted/packed payload.
    """

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)


# ==========================================
# STREAM CONTEXT CLASSIFICATION
# ==========================================
#
# Used by modules/parsers/streams.py to recognize streams that declare
# themselves as images or embedded font programs, so entropy/shellcode
# heuristics — which assume high entropy is otherwise "unexplained" —
# aren't applied to content that is legitimately high-entropy by design
# (JPEG/DCT image data, compressed/hinted font tables). This is what
# lets the analyzer ignore normal image and font streams instead of
# flagging nearly every one of them.

_IMAGE_FILTER_KEYWORDS = (
    "DCTDecode", "CCITTFaxDecode", "JBIG2Decode", "JPXDecode"
)

_FONT_KEYWORDS = (
    "FontFile3", "FontFile2", "FontFile",
    "Type1C", "CIDFontType0C", "OpenType",
)

_GENERIC_COMPRESSION_FILTERS = (
    "FlateDecode", "LZWDecode", "ASCII85Decode",
    "ASCIIHexDecode", "RunLengthDecode",
)


def classify_stream_context(preceding_dict_text):
    """
    Classify a stream using the PDF object dictionary text immediately
    preceding its `stream` keyword.

    Returns one of:
      "font"       — declares an embedded font program
      "image"      — declares image data or an image-specific filter
      "compressed" — declares a generic (non-image) compression filter
      "unknown"    — no recognizable declaration either way

    This is a text-based declaration check, not a guarantee of actual
    content — but a stream that lies about its own type (claims to be
    a font/image while hiding something else) is itself a meaningful,
    separate signal from raw entropy, and is out of scope for this
    helper.
    """

    if any(k in preceding_dict_text for k in _FONT_KEYWORDS):
        return "font"

    if "/Image" in preceding_dict_text or any(
        k in preceding_dict_text for k in _IMAGE_FILTER_KEYWORDS
    ):
        return "image"

    if any(k in preceding_dict_text for k in _GENERIC_COMPRESSION_FILTERS):
        return "compressed"

    return "unknown"


# ==========================================
# DECOMPRESSION
# ==========================================

def _try_zlib(data):
    """Standard FlateDecode, then a raw-deflate fallback."""

    try:
        return zlib.decompress(data)

    except zlib.error:

        try:
            # Some PDF streams omit the zlib header
            return zlib.decompress(data, -15)

        except zlib.error:
            return None


def _try_ascii_prefilter(data):
    """
    Attempt ASCIIHexDecode or ASCII85Decode on raw stream bytes, as a
    pre-pass before a second decompression attempt. Only applied when
    the byte content is actually consistent with the respective
    encoding, so this never misinterprets genuinely binary data as
    text-encoded.

    Handles the common chained-filter case
    ([/ASCII85Decode /FlateDecode] or [/ASCIIHexDecode /FlateDecode])
    that a single zlib attempt alone can't unwrap.
    """

    stripped = data.strip()

    if not stripped:
        return None

    # ASCIIHexDecode: hex digits/whitespace only, terminated by '>'
    if stripped.endswith(b">") and re.fullmatch(
        rb"[0-9A-Fa-f\s]*>", stripped
    ):
        try:
            hex_digits = re.sub(rb"[^0-9A-Fa-f]", b"", stripped[:-1])
            if len(hex_digits) % 2:
                hex_digits += b"0"
            return bytes.fromhex(hex_digits.decode("ascii"))
        except ValueError:
            return None

    # ASCII85Decode: PDF variant delimited by '<~' ... '~>'
    if stripped.startswith(b"<~") and stripped.endswith(b"~>"):
        try:
            return base64.a85decode(stripped[2:-2])
        except ValueError:
            return None

    return None


def decompress_stream(data):
    """
    Attempt to decompress stream bytes.

    Tries, in order:
      1. Standard zlib (FlateDecode) — the common case.
      2. Raw deflate (missing zlib header — seen in some malformed or
         hand-crafted PDFs).
      3. A single ASCIIHexDecode/ASCII85Decode pre-pass, followed by
         another zlib attempt on the result — handles the common
         chained-filter case a single zlib attempt can't unwrap.

    Returns decompressed bytes, or None if none of the above worked.
    """

    result = _try_zlib(data)
    if result is not None:
        return result

    prefiltered = _try_ascii_prefilter(data)
    if prefiltered is not None:
        result = _try_zlib(prefiltered)
        if result is not None:
            return result

    return None


def validate_pdf_header(pdf_path):
    """
    Check that the file starts with %PDF- magic bytes.
    Returns True if valid, False if spoofed/invalid.
    """

    try:

        with open(pdf_path, "rb") as f:
            header = f.read(8)

        return header.startswith(b"%PDF-")

    except OSError as e:

        log.error(f"Could not read PDF header: {e}")
        return False


# ==========================================
# SHELLCODE HEURISTICS
# ==========================================
#
# Isolated static byte signatures (a bare \x90\x90\x90\x90, or a single
# two/three-byte "prologue") are cheap to defeat and fire on ordinary
# binary and compressed content often enough to be unreliable on their
# own. This engine instead combines independent structural signals and
# only reports a finding once enough of them agree — trading a small
# amount of recall for a large reduction in false positives.

# A NOP run this long is a strong heap-spray/sled indicator on its own.
_NOP_SLED_HIGH_CONFIDENCE_LEN = 64
# A shorter run only counts alongside another corroborating signal.
_NOP_SLED_MEDIUM_CONFIDENCE_LEN = 16

# Common x86/x86-64 opcode bytes for call/jmp/push/pop/mov/arithmetic —
# used only as a density estimate of how "code-like" a byte window
# looks, never as a standalone match. Genuinely random or compressed
# bytes land near len(set)/256 ≈ 0.17; real machine code clusters these
# bytes far more densely.
_COMMON_X86_OPCODES = frozenset(
    list(range(0x50, 0x60)) +               # PUSH/POP r32/r64
    [0x8B, 0x89, 0x8D] +                     # MOV r/m, MOV r, LEA
    [0xE8, 0xE9, 0xEB] +                     # CALL rel32, JMP rel32/rel8
    [0xC3, 0xC2] +                           # RET, RET imm16
    [0x83, 0x81, 0x01, 0x03, 0x29, 0x2B] +   # ADD/SUB variants
    [0x31, 0x33, 0x85] +                     # XOR, TEST
    [0x74, 0x75, 0x0F]                       # JZ/JNZ, two-byte opcode prefix
)

_OPCODE_DENSITY_WINDOW = 48
_OPCODE_DENSITY_THRESHOLD = 0.32


def _longest_byte_run(data, byte_value):
    """Length of the longest contiguous run of `byte_value` in data."""

    longest = 0
    current = 0

    for b in data:
        if b == byte_value:
            current += 1
            longest = max(longest, current)
        else:
            current = 0

    return longest


def _max_opcode_density(data, window=_OPCODE_DENSITY_WINDOW):
    """
    Slide a fixed-size window across `data` and return the highest
    fraction of bytes in any window that fall in _COMMON_X86_OPCODES.
    A coarse, deliberately conservative proxy for "does this look like
    machine code" — used only in combination with other signals below,
    never alone.
    """

    if not data:
        return 0.0

    if len(data) < window:
        window = len(data)

    if window == 0:
        return 0.0

    best = 0.0
    step = max(1, window // 4)

    for start in range(0, len(data) - window + 1, step):
        chunk = data[start:start + window]
        hits = sum(1 for b in chunk if b in _COMMON_X86_OPCODES)
        density = hits / len(chunk)
        best = max(best, density)

    return round(best, 2)


def _find_getpc_idiom(data):
    """
    Look for the classic "GetPC" idiom used throughout real-world
    position-independent shellcode: a CALL to the very next
    instruction (E8 00 00 00 00) immediately followed by a POP reg,
    which leaves the current instruction pointer in a general-purpose
    register — plus the FPU-based variant (FNSTENV after a dummy FPU
    op). This checks the *relationship* between adjacent instructions,
    which is far more specific to real shellcode than any single
    isolated byte sequence.

    Returns a list of byte offsets where the idiom was found.
    """

    offsets = []

    call_next = re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]")
    offsets.extend(m.start() for m in call_next.finditer(data))

    fpu_getpc = re.compile(rb"\xd9\xee.{0,4}\xd9[\x74\x7c]\x24")
    offsets.extend(m.start() for m in fpu_getpc.finditer(data))

    return offsets


def detect_shellcode_patterns(data):
    """
    Scan byte data for shellcode using corroborated structural
    heuristics: NOP-sled run length, the GetPC call/pop (or FPU) idiom,
    and x86 opcode-byte density. A finding is only reported when at
    least two independent signals agree, or a single signal (a very
    long NOP run) is strong enough to stand alone.

    Returns a list of human-readable finding strings — empty if
    nothing here clears the confidence bar.
    """

    findings = []

    if isinstance(data, str):
        data = data.encode(errors="replace")

    if len(data) < 32:
        return findings

    nop_run = _longest_byte_run(data, 0x90)
    getpc_offsets = _find_getpc_idiom(data)
    density = _max_opcode_density(data)
    density_elevated = density >= _OPCODE_DENSITY_THRESHOLD

    if nop_run >= _NOP_SLED_HIGH_CONFIDENCE_LEN:
        findings.append(
            f"NOP sled of {nop_run} contiguous bytes (confidence: high) "
            f"— consistent with heap-spray shellcode staging"
        )

    elif nop_run >= _NOP_SLED_MEDIUM_CONFIDENCE_LEN and density_elevated:
        findings.append(
            f"NOP-like run of {nop_run} bytes alongside elevated x86 "
            f"opcode density ({density}) (confidence: medium) — "
            f"possible shellcode sled"
        )

    if getpc_offsets:
        if density_elevated:
            findings.append(
                f"GetPC idiom (call/pop or FPU-based) at offset(s) "
                f"{getpc_offsets[:3]} with elevated opcode density "
                f"({density}) (confidence: high) — classic "
                f"position-independent shellcode pattern"
            )
        else:
            findings.append(
                f"GetPC idiom (call/pop or FPU-based) at offset(s) "
                f"{getpc_offsets[:3]} (confidence: medium) — common in "
                f"position-independent shellcode, seen here without "
                f"other corroborating indicators"
            )

    return findings


def is_suspicious_filename(fname):
    """
    Check if an embedded filename has a dangerous extension.
    """

    dangerous_extensions = [
        ".exe", ".dll", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".scr",
        ".hta", ".jar", ".sh", ".py"
    ]

    lower = fname.lower()

    return any(lower.endswith(ext) for ext in dangerous_extensions)


def find_balanced_parens_content(text, open_paren_index):
    """
    Extract the content of a PDF string literal given the index of its
    opening '(' in `text`. Returns the content between the parens
    (excluding the delimiters), or None if the string is unterminated
    or `open_paren_index` doesn't actually point at '('.

    PDF string literals allow parentheses to appear unescaped as long
    as they're balanced (e.g. "(a (nested) string)" is one literal,
    not two), and "\\(" / "\\)" are escaped literals that don't count
    toward balance. A naive "match up to the next )" regex gets both
    of these wrong and truncates real JavaScript source that contains
    parens of its own (i.e. essentially all real JavaScript) — this
    walks the string properly instead.

    Added to support accurate /JS (...) extraction in
    modules/parsers/javascript.py.
    """

    if (
        open_paren_index is None
        or open_paren_index < 0
        or open_paren_index >= len(text)
        or text[open_paren_index] != "("
    ):
        return None

    depth = 0
    i = open_paren_index
    content_start = open_paren_index + 1
    length = len(text)

    while i < length:

        ch = text[i]

        if ch == "\\" and i + 1 < length:
            # Escaped character (e.g. \( \) \\ ) — skip both bytes,
            # it never affects paren balance.
            i += 2
            continue

        if ch == "(":
            depth += 1

        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[content_start:i]

        i += 1

    # Reached end of text without the parens balancing out — the
    # string literal is truncated/unterminated in what we captured.
    return None


def find_balanced_parens_bytes(data, open_paren_index):
    """
    Byte-string counterpart of find_balanced_parens_content(), for
    callers that need to extract a PDF string literal (e.g. a /F(...)
    or /UF(...) filename) directly from raw file bytes rather than
    decoded text. Same balanced-parens / escape-aware walk as the text
    version above, operating on bytes instead of str.

    Added to support accurate embedded-file filename extraction in
    modules/parsers/embedded.py, replacing a naive "[^)]+" byte regex
    that truncated or misparsed on nested or escaped parentheses.
    """

    if (
        open_paren_index is None
        or open_paren_index < 0
        or open_paren_index >= len(data)
        or data[open_paren_index:open_paren_index + 1] != b"("
    ):
        return None

    depth = 0
    i = open_paren_index
    content_start = open_paren_index + 1
    length = len(data)

    while i < length:

        ch = data[i:i + 1]

        if ch == b"\\" and i + 1 < length:
            # Escaped character (e.g. \( \) \\ ) — skip both bytes,
            # it never affects paren balance.
            i += 2
            continue

        if ch == b"(":
            depth += 1

        elif ch == b")":
            depth -= 1
            if depth == 0:
                return data[content_start:i]

        i += 1

    # Reached end of data without the parens balancing out — the
    # string literal is truncated/unterminated in what we captured.
    return None