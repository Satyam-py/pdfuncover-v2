# modules/parsers/javascript.py
#
# JavaScript / OpenAction detection and decoded-preview extraction.
#
# ==========================================================================
# REDESIGNED DETECTION STRATEGY (schema-compatible with the original)
# ==========================================================================
#
# The original implementation flagged "JavaScript Detected" whenever the
# bare word "JavaScript" showed up anywhere pdf-parser's --search found it,
# and scanned an entire `strings <pdf>` dump for "suspicious keywords" —
# both of which are prone to false positives from ordinary document text
# (a Title like "JavaScript Guide", a Producer string, visible page
# content, etc.), and the keyword scan used naive substring matching, so
# e.g. "eval" also matched inside the word "medieval".
#
# This version detects off real PDF structure instead:
#   - JavaScript is only reported when the actual PDF name tokens that
#     define a JavaScript action are present: an Action's /S /JavaScript
#     subtype, and/or a /JS entry (both are slash-prefixed PDF name/key
#     tokens — they don't collide with plain English text the way a bare
#     "JavaScript" substring search does).
#   - OpenAction is only reported when /OpenAction is followed by an
#     actual target (an indirect object reference or an inline action
#     dictionary), not just present as a stray token.
#   - The decoded preview and the suspicious-keyword scan are both scoped
#     to the real JavaScript content we found (the /JS string literal, or
#     the resolved indirect object when /JS points elsewhere) instead of
#     the whole file, and keyword matching uses word-boundary regex so
#     "eval" no longer matches inside "medieval".
#   - Only one pdf-parser invocation is needed for the primary scan
#     (previously two — one per search term), plus at most one further
#     invocation only when JavaScript is indirect and needs resolving.
#
# Public return schema, function name, and call signature are unchanged,
# preserving CLI/report/orchestrator compatibility:
#     analyze_javascript(pdf_path, strings_output) -> {
#         "JavaScript Detected": bool,
#         "OpenAction Found": bool,
#         "Suspicious Keywords": [str, ...],
#         "Decoded JS Preview": str,
#     }
#     (+ "Error" key when pdf-parser is unavailable, as before.)

import os
import re
import shutil
import logging
from typing import Dict, List, Optional

from modules.parsers.helpers import (
    run_command,
    decode_pdf_string,
    find_balanced_parens_content,
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
# PDF STRUCTURAL TOKEN PATTERNS
# ==========================================
#
# Real PDF dictionary keys/names are always "/" immediately followed by
# the token, with no letters attached on either side. Matching the slash
# form (rather than the bare word) is what lets an actual /JavaScript or
# /JS key be told apart from the same word appearing as plain text.

# Action dictionary subtype: /S /JavaScript — the canonical marker of a
# JavaScript action per the PDF spec.
_ACTION_SUBTYPE_RE = re.compile(r"/S\s*/JavaScript\b")

# The /JS entry itself, e.g. "/JS (...)" or "/JS 12 0 R". This token is
# specific enough (a two-letter, slash-prefixed, all-caps PDF key) that
# it essentially never appears as coincidental text.
_JS_KEY_RE = re.compile(r"/JS\b")

# /OpenAction must actually point somewhere — an indirect reference or
# an inline action dictionary — to count as real, not just appear as a
# bare token near unrelated text.
_OPENACTION_TARGET_RE = re.compile(
    r"/OpenAction\s*(?:\d+\s+\d+\s+R|<<)"
)

# Opening of a direct string-literal /JS entry: "/JS (" — the index of
# the "(" is what we hand to find_balanced_parens_content().
_JS_LITERAL_OPEN_RE = re.compile(r"/JS\s*\(")

# Indirect /JS reference: "/JS 12 0 R"
_JS_INDIRECT_REF_RE = re.compile(r"/JS\s+(\d+)\s+\d+\s+R")

# Suspicious keywords considered obfuscation/exploit indicators. Same
# list as the original implementation — no detections added or removed,
# only how (and where) they're matched.
SUSPICIOUS_KEYWORDS = [
    "eval",
    "unescape",
    "app.launchURL",
    "this.exportDataObject",
    "submitForm",
    "getAnnots",
    "app.alert",
    "util.printf",
    "Collab.collectEmailInfo",
    "fromCharCode",
]

# Word-boundary pattern per keyword: matches only when the keyword is
# not directly attached to other identifier characters, so "eval" can't
# match inside "medieval"/"evaluate" and "app.alert" can't match inside
# a longer dotted identifier.
_KEYWORD_PATTERNS = {
    keyword: re.compile(
        r"(?<![A-Za-z0-9_])" + re.escape(keyword) + r"(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )
    for keyword in SUSPICIOUS_KEYWORDS
}


# ==========================================
# STRUCTURAL DETECTION HELPERS
# ==========================================

def _has_real_javascript_action(pdf_object_text: str) -> bool:
    """
    True only if actual PDF JavaScript-action syntax is present: the
    /S /JavaScript action subtype, and/or a /JS entry. Both are
    structural PDF name/key tokens, not incidental text.
    """

    return bool(
        _ACTION_SUBTYPE_RE.search(pdf_object_text)
        or _JS_KEY_RE.search(pdf_object_text)
    )


def _has_real_openaction(pdf_object_text: str) -> bool:
    """
    True only if /OpenAction appears as an actual key pointing at a
    target (an indirect reference or inline dictionary) — not as a
    bare word floating in unrelated text.
    """

    return bool(_OPENACTION_TARGET_RE.search(pdf_object_text))


def _extract_literal_js_spans(pdf_object_text: str) -> List[str]:
    """
    Decode every direct string-literal /JS (...) entry in the text,
    using proper balanced-parenthesis parsing (see
    helpers.find_balanced_parens_content) rather than a "stop at the
    next )" regex, which truncates real JS source containing its own
    parens.
    """

    spans: List[str] = []

    for match in _JS_LITERAL_OPEN_RE.finditer(pdf_object_text):

        open_paren_index = match.end() - 1  # index of the "(" itself
        raw_content = find_balanced_parens_content(pdf_object_text, open_paren_index)

        if raw_content is not None:
            spans.append(decode_pdf_string(raw_content))

    return spans


def _resolve_indirect_js(pdf_object_text: str, pdf_path: str) -> Optional[str]:
    """
    When /JS points at another object ("/JS N G R") instead of holding
    a literal string, fetch and decode that object directly rather than
    guessing from surrounding text. Returns decoded content, or None if
    there's no indirect reference or it couldn't be resolved.
    """

    ref = _JS_INDIRECT_REF_RE.search(pdf_object_text)

    if not ref:
        return None

    obj_num = ref.group(1)

    target_output = run_command(
        ["pdf-parser", "--object", obj_num, "--filter", "--raw", pdf_path]
    )

    if not target_output.strip():
        return None

    return decode_pdf_string(target_output)


def _find_suspicious_keywords(text: str) -> List[str]:
    """
    Return the subset of SUSPICIOUS_KEYWORDS that appear in `text` as
    whole tokens (word-boundary match), preserving original list order.
    """

    return [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if _KEYWORD_PATTERNS[keyword].search(text)
    ]


def _clean_preview(text: str, max_len: int = 200) -> str:
    """Collapse whitespace and truncate for display, as before."""
    return re.sub(r"\s+", " ", text).strip()[:max_len]


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def analyze_javascript(pdf_path: str, strings_output: str) -> Dict[str, object]:
    """
    Detect embedded JavaScript, OpenAction triggers, suspicious
    keyword usage, and decode a preview of the JS content.

    `strings_output` is accepted for signature compatibility with the
    orchestrator (which computes it once and shares it across parsers)
    but is intentionally not used for detection here: a whole-file
    strings dump includes visible page text, metadata, and comments,
    which is exactly the source of false positives this redesign
    removes. Detection instead runs against pdf-parser's parsed object
    output, checked for real PDF JavaScript-action syntax.

    Returns the same "JavaScript" dict the original
    extract_embedded_objects() produced:
        {
            "JavaScript Detected": bool,
            "OpenAction Found": bool,
            "Suspicious Keywords": List[str],
            "Decoded JS Preview": str,
        }
    (plus "Error" if pdf-parser is unavailable, as before.)
    """

    js_data: Dict[str, object] = {
        "JavaScript Detected": False,
        "OpenAction Found": False,
        "Suspicious Keywords": [],
        "Decoded JS Preview": ""
    }

    if not shutil.which("pdf-parser"):
        js_data["Error"] = "pdf-parser not installed"
        return js_data

    # Single pdf-parser pass over the whole file instead of two separate
    # --search invocations — pdf-parser parses the entire object table
    # internally either way, so one full dump covers both checks.
    parsed_output = run_command(["pdf-parser", pdf_path])

    js_data["JavaScript Detected"] = _has_real_javascript_action(parsed_output)
    js_data["OpenAction Found"] = _has_real_openaction(parsed_output)

    if not js_data["JavaScript Detected"]:
        return js_data

    # Scope both the keyword scan and the preview to real JS content
    # only — direct string literals first, falling back to resolving
    # an indirect /JS reference (at most one extra pdf-parser call).
    js_spans = _extract_literal_js_spans(parsed_output)

    if not js_spans:
        resolved = _resolve_indirect_js(parsed_output, pdf_path)
        if resolved:
            js_spans = [resolved]

    if js_spans:
        combined_js_text = "\n".join(js_spans)
        js_data["Suspicious Keywords"] = _find_suspicious_keywords(combined_js_text)
        js_data["Decoded JS Preview"] = _clean_preview(js_spans[0])
    else:
        # JavaScript action confirmed structurally, but its content
        # couldn't be isolated (e.g. unusual encoding) — fall back to
        # scanning the parsed object output itself so a real, if
        # heavily obfuscated, script still gets its keywords surfaced
        # rather than silently reporting none.
        js_data["Suspicious Keywords"] = _find_suspicious_keywords(parsed_output)

    return js_data