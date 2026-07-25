# modules/parsers/iocs.py
#
# Indicator-of-compromise extraction: URLs, domains, and IP addresses.
#
# REDESIGN NOTES (final implementation):
#
#   - URL matching now requires a plausible host after the scheme
#     (a domain-shaped run of labels ending in a real-looking TLD, an
#     IPv4 address, or "localhost") instead of "https?:// then any
#     non-whitespace/bracket run". The old pattern matched happily on
#     garbage `strings` noise that merely contained the substring
#     "http://" — this is the main source of false positives removed.
#     Path/query length is capped so a single corrupted binary run
#     can't produce one enormous "URL".
#   - Every candidate URL is parsed with urllib.parse and rejected
#     unless it has a real scheme + netloc, closing off malformed
#     leftovers the regex alone might still admit.
#   - Domains are validated (label length, total length) and a
#     dotted-decimal-looking prefix (e.g. "192.168.1.co") is rejected
#     as an IP/TLD collision rather than reported as a hostname.
#     Hostnames are also pulled from already-validated URLs, so a
#     legitimate host using a TLD outside the curated list isn't lost.
#   - IP matching uses boundary lookarounds so a 4-octet run can't be
#     sliced out of a longer dotted-number sequence (e.g. a version
#     string), and rejects non-canonical leading-zero octets.
#   - All three output lists de-duplicate via a `seen` set while
#     preserving first-seen order (the old code did an O(n) `in` scan
#     against a growing list for the same effect).
#   - decode_pdf_string (shared helper) was extended to also collapse
#     PDF line-continuation escapes, so long URLs/domains wrapped
#     across lines in the source no longer get torn in half before
#     the regexes below ever see them.
#
# Public API (extract_iocs(pdf_path, strings_output) -> dict) and the
# extraction logic/regexes above are unchanged.
#
# STEP 9 CHANGE: this module previously called
# modules/parsers/ioc_enrichment.py (which in turn called the older
# modules.threat_intel.ThreatIntelManager) at the end of extract_iocs()
# to attach a "Threat Intelligence" key. That enrichment step has been
# REMOVED from here — detection/extraction logic below is otherwise
# byte-for-byte unchanged.
#
# Enrichment is now performed by modules/threat_intel_pipeline.py,
# called once from the orchestrator (modules/embedded_extraction.py)
# immediately after extract_iocs() returns, via the new, frozen
# Threat Intelligence engine (modules/threat_intel/engine.py). Per
# Step 9's requirement that "the orchestration layer should call the
# Threat Intelligence engine" and enrichment logic not be duplicated
# into other modules, extract_iocs() now does exactly one thing:
# extraction. The orchestrator attaches the resulting
# "Threat Intelligence" key to this function's returned dict in the
# same shape it always had, so every downstream consumer
# (modules.correlation, modules.attack_chain, modules.evidence_explorer,
# modules.report) needs no changes.

import os
import re
import shutil
import logging

from urllib.parse import urlparse

from modules.parsers.helpers import run_command, decode_pdf_string


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
# URL EXTRACTION
# ==========================================
#
# Requires a domain-shaped or IPv4 host after the scheme, rather than
# "any non-whitespace run", so binary noise that merely contains the
# substring "http://" doesn't get reported as a URL.

_URL_PATTERN = re.compile(
    r"https?://"
    r"(?:"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}"  # domain
    r"|(?:\d{1,3}\.){3}\d{1,3}"                                            # IPv4
    r"|localhost"
    r")"
    r"(?::\d{1,5})?"
    r"(?:[/?#][^\s<>()'\"]{0,500})?"
)


def _clean_url(raw_url):
    """
    Strip trailing punctuation/quote noise a regex match commonly
    picks up (closing parens, sentence punctuation, quote marks), then
    validate the result actually parses as an http(s) URL with a real
    host. Returns None if it doesn't hold up.
    """

    url = raw_url.strip()

    trailing_junk = ").,]};>'\""
    while url and url[-1] in trailing_junk:
        url = url[:-1]

    url = url.replace("\\", "")

    if not url:
        return None

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return None

    if not parsed.hostname:
        return None

    return url


# ==========================================
# DOMAIN EXTRACTION
# ==========================================

_DOMAIN_TLDS = (
    "com|org|net|edu|gov|mil|io|co|info|biz|ru|cn|in|us|uk|de|fr|nl|"
    "xyz|top|club|online|site|tk|ml|ga|cf|gq|click|link|pw|cc|me|app|dev"
)

_DOMAIN_PATTERN = re.compile(
    rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+"
    rf"(?:{_DOMAIN_TLDS})\b",
    re.IGNORECASE
)

_IP_LIKE_PREFIX_RE = re.compile(r"^\d{1,3}$")


def _is_valid_domain(domain):
    """
    Reject matches that are structurally invalid as hostnames, and
    reject the specific false-positive pattern of a dotted-decimal
    number sequence that happens to end in something matching a TLD
    (e.g. "192.168.1.co") — that's an IP address, not a domain.
    """

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    if len(domain) > 253:
        return False

    if any(len(label) > 63 or not label for label in labels):
        return False

    leading = labels[:-1]

    if len(leading) >= 3 and all(_IP_LIKE_PREFIX_RE.match(l) for l in leading):
        return False

    return True


# ==========================================
# IP EXTRACTION
# ==========================================
#
# Boundary lookarounds keep this from slicing a 4-octet run out of a
# longer dotted-number sequence (e.g. matching the first four parts of
# a 5+ part version string).

_IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _is_valid_ip(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            # Non-canonical leading zero (e.g. "01") — ambiguous and
            # essentially never a genuine IP literal in the wild.
            return False
        try:
            if not (0 <= int(part) <= 255):
                return False
        except ValueError:
            return False

    return True


# ==========================================
# MAIN ENTRY POINT
# ==========================================

def extract_iocs(pdf_path, strings_output):
    """
    Extract URLs, domains, and IP addresses referenced inside the PDF.

    `strings_output` is the `strings <pdf_path>` output computed once
    by the orchestrator and shared across parsers.

    Returns the same "IOCs" dict shape the original
    extract_embedded_objects() produced:
        {"URLs": [...], "Domains": [...], "IPs": [...]}

    STEP 9: this function no longer performs Threat Intelligence
    enrichment itself. The orchestrator (modules/embedded_extraction.py)
    calls modules.threat_intel_pipeline.enrich_extracted_iocs() on this
    function's return value immediately afterward, attaching the same
    "Threat Intelligence" key downstream consumers have always read —
    now backed by the new, frozen Threat Intelligence engine instead of
    the previous system. See modules/threat_intel_pipeline.py.
    """

    ioc_data = {
        "URLs": [],
        "Domains": [],
        "IPs": []
    }

    uri_output = ""
    link_output = ""

    if shutil.which("pdf-parser"):

        try:
            # /URI with slash matches Link action dictionaries
            uri_output = run_command(
                ["pdf-parser", "--search", "/URI", pdf_path]
            )
            link_output = run_command(
                ["pdf-parser", "--search", "Link", pdf_path]
            )
        except Exception as e:
            log.error(f"pdf-parser search failed during IOC extraction: {e}")

    # Decode ALL sources before regex — raw octals/line-continuations
    # won't match otherwise.
    try:
        decoded_strings = decode_pdf_string(strings_output or "")
        decoded_uri = decode_pdf_string(uri_output)
        decoded_link = decode_pdf_string(link_output)
    except Exception as e:
        log.error(f"Failed to decode PDF strings for IOC extraction: {e}")
        decoded_strings = strings_output or ""
        decoded_uri = uri_output
        decoded_link = link_output

    combined_output = "\n".join([
        decoded_strings,
        decoded_uri,
        decoded_link
    ])

    # ------------------------------------------
    # URL extraction
    # ------------------------------------------

    clean_urls = []
    seen_urls = set()

    for match in _URL_PATTERN.finditer(combined_output):
        url = _clean_url(match.group(0))
        if url and url not in seen_urls:
            seen_urls.add(url)
            clean_urls.append(url)

    # ------------------------------------------
    # Domain extraction
    # ------------------------------------------

    clean_domains = []
    seen_domains = set()

    for match in _DOMAIN_PATTERN.finditer(combined_output):
        domain = match.group(0).lower().strip(".")
        if _is_valid_domain(domain) and domain not in seen_domains:
            seen_domains.add(domain)
            clean_domains.append(domain)

    # Fold in hostnames from already-validated URLs too, in case they
    # use a TLD outside the curated list above.
    for url in clean_urls:
        host = urlparse(url).hostname
        if not host:
            continue
        host = host.lower()
        if _IP_PATTERN.fullmatch(host):
            continue
        if host not in seen_domains:
            seen_domains.add(host)
            clean_domains.append(host)

    # ------------------------------------------
    # IP extraction with octet validation
    # ------------------------------------------

    clean_ips = []
    seen_ips = set()

    for match in _IP_PATTERN.finditer(combined_output):
        ip = match.group(0)
        if _is_valid_ip(ip) and ip not in seen_ips:
            seen_ips.add(ip)
            clean_ips.append(ip)

    ioc_data["URLs"] = clean_urls
    ioc_data["Domains"] = clean_domains
    ioc_data["IPs"] = clean_ips

    return ioc_data