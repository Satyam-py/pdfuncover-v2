# modules/threat_intel/providers/whois.py
"""
WHOIS provider, following the same conventions as the existing
providers (VirusTotal, OTX, URLScan, AbuseIPDB).

WHOIS is a Context Provider — it never determines whether a domain is
malicious, it only reports registration facts. Accordingly this
provider returns only DomainContext, never a ReputationFinding.

Only lookup_domain() is implemented; WHOIS supports domains only, so
no stub methods exist for URL/IP/Hash — unsupported types are
expressed purely through ProviderRegistration.supported_types.

Raw WHOIS text never leaves this module — every field is normalized
into ThreatIntelResult / DomainContext before being returned.

DomainContext has dedicated fields only for registrar and
creation_date. Updated Date, Expiration Date, Name Servers, and Domain
Status have no dedicated field, so — following the same convention
already used by other providers for "extra" context (e.g.
AbuseIPDB/OTX packing facts into `categories` as labeled strings) —
they are appended into DomainContext.dns_records as labeled entries.

VALIDATION NOTE: lookup_domain() previously treated any WHOIS response
that came back over the socket as a successful lookup, with no check
that (a) the input was even a syntactically valid, publicly-delegated
domain, or (b) the response actually contained registration data
rather than a "not found"/"no referral" message. That let internal-
only or otherwise non-public names (e.g. "internal.corp") report
success with an empty DomainContext. Two checks were added to close
that gap:
    1. _validate_public_domain() rejects malformed input and known
       reserved/special-use or conventionally-internal TLDs *before*
       any network call is made.
    2. _request() now treats "IANA has no referral for this TLD" and
       "the registry says no match" as LookupError.NOT_FOUND instead
       of silently returning whatever text it received as success.
"""

import os
import re
import socket

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    DomainContext,
    LookupError,
)
from modules.threat_intel.providers.helpers import normalize_domain

from modules.logging_config import get_logger
log = get_logger(__name__, "analyzer.log")

PROVIDER_NAME = "WHOIS"

_IANA_WHOIS_SERVER = "whois.iana.org"
_WHOIS_PORT = 43
_TIMEOUT = 10
_MAX_RESPONSE_BYTES = 65536


# ==========================================
# DOMAIN VALIDATION (pre-flight, no network call)
# ==========================================
#
# WHOIS only has meaning for a syntactically valid, fully-qualified
# name under a TLD that is actually delegated in the public root zone.
# Reserved/special-use names (RFC 6761 "test"/"example"/"invalid",
# RFC 6762 "local", RFC 7686 "onion", RFC 8375 "home.arpa") and common
# enterprise-internal pseudo-TLDs ("corp", "internal", "lan", ...) will
# never have a public WHOIS record — querying for them at all is the
# root cause of the false "success" this module used to report.

_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Reserved/special-use TLDs (RFC 6761, RFC 6762, RFC 7686) plus TLDs
# commonly used for internal/enterprise-only naming that ICANN has
# never delegated publicly. Not exhaustive by design — this blocks the
# well-known cases; genuinely unknown/typo'd TLDs are still caught by
# the "no IANA referral" check in _request() below.
_NON_PUBLIC_TLDS = frozenset({
    # RFC 6761 — special-use
    "test", "example", "invalid", "localhost",
    # RFC 6762 — multicast DNS
    "local",
    # RFC 7686 — Tor hidden services (not a public WHOIS-delegated TLD)
    "onion",
    # RFC 8375 — home networking
    "arpa",
    # Common internal/enterprise-only conventions, never delegated
    "internal", "intranet", "corp", "home", "lan", "private",
    "localdomain", "domain", "network", "workgroup",
})


def _validate_public_domain(domain):
    """
    Best-effort pre-flight check that `domain` is a syntactically
    valid, potentially publicly-registrable domain name.

    Returns None if the domain passes validation, or a short
    human-readable reason string if it should be rejected outright
    (used as the WHOIS lookup's error_message). This does NOT
    guarantee the domain is actually registered — only that it's
    worth spending a network round-trip to find out.
    """

    if not domain or not domain.strip():
        return "empty domain"

    candidate = domain.strip().strip(".").lower()

    if not candidate:
        return "empty domain"

    if len(candidate) > 253:
        return f"domain exceeds maximum length ({len(candidate)} chars)"

    labels = candidate.split(".")

    if len(labels) < 2:
        return f"'{candidate}' is not a fully-qualified domain (missing a TLD)"

    for label in labels:
        if not _LABEL_RE.match(label):
            return f"'{candidate}' contains an invalid label ('{label}')"

    if all(label.isdigit() for label in labels):
        return f"'{candidate}' looks like an IP address literal, not a domain"

    tld = labels[-1]

    if tld in _NON_PUBLIC_TLDS:
        return (
            f"'.{tld}' is a reserved/special-use or internal-only TLD, "
            f"not a publicly delegated top-level domain"
        )

    return None


# ==========================================
# TRANSPORT HELPER
# ==========================================

def _query_server(server, domain):
    """Send a single raw WHOIS query to `server` and return the decoded response."""

    with socket.create_connection((server, _WHOIS_PORT), timeout=_TIMEOUT) as sock:
        sock.sendall((domain + "\r\n").encode("utf-8", errors="replace"))

        chunks = []
        total = 0

        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= _MAX_RESPONSE_BYTES:
                break

    return b"".join(chunks).decode("utf-8", errors="replace")


def _find_referral(iana_text):
    """Pull the authoritative registry WHOIS server out of IANA's referral response."""

    for line in iana_text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()

        if lowered.startswith("refer:") or lowered.startswith("whois:"):
            _, _, value = stripped.partition(":")
            value = value.strip()
            if value:
                return value

    return None


# Phrases registries/IANA use to say "there is no record for this
# name" instead of returning an error status. WHOIS has no standard
# machine-readable status code, so this is necessarily a best-effort
# text match — kept to the handful of phrasings that are effectively
# universal across registries, rather than an exhaustive list.
_NOT_FOUND_PATTERNS = (
    "no match",
    "not found",
    "no entries found",
    "no data found",
    "no object found",
    "domain not found",
    "no matching record",
    "status: free",
    "status: available",
    "available for registration",
    "this query returned 0 objects",
)


def _looks_like_not_found(text):
    """True if `text` reads as a registry/IANA "no record" response
    rather than actual registration data."""

    lowered = (text or "").lower()
    return any(pattern in lowered for pattern in _NOT_FOUND_PATTERNS)


def _request(domain):
    """
    Resolve the authoritative WHOIS server via IANA, then query it.
    Returns (raw_text, LookupError) — exactly one of the two is None.

    Two "no record" outcomes are now distinguished from a genuine
    successful lookup, both reported as LookupError.NOT_FOUND rather
    than falling through as success:
      - IANA has no referral at all for this TLD (the TLD isn't
        delegated in the public root zone, or IANA itself reports no
        match) — previously this silently returned IANA's own
        boilerplate text as if it were domain data.
      - The registry WHOIS server responds with recognizable "no
        match"/"available" text instead of registration fields.
    """

    try:
        iana_text = _query_server(_IANA_WHOIS_SERVER, domain)

    except socket.timeout:
        return None, LookupError.NETWORK_ERROR

    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        log.error(f"WHOIS IANA referral lookup failed for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR

    referral = _find_referral(iana_text)

    if not referral:
        # No referral means IANA doesn't recognize this TLD as
        # delegated (or explicitly reports no match) — there is no
        # public registry to query, so this is a genuine "not found",
        # not a successful lookup with empty content.
        log.error(
            f"No IANA referral for domain '{domain}' — TLD is not "
            f"delegated in the public root zone or is unrecognized"
        )
        return None, LookupError.NOT_FOUND

    text = iana_text

    if referral.lower() != _IANA_WHOIS_SERVER:

        try:
            text = _query_server(referral, domain)

        except socket.timeout:
            return None, LookupError.NETWORK_ERROR

        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            log.error(f"WHOIS registry lookup failed for {domain} via {referral}: {e}")
            return None, LookupError.NETWORK_ERROR

    if _looks_like_not_found(text):
        log.error(f"WHOIS registry reports no match for domain '{domain}'")
        return None, LookupError.NOT_FOUND

    return text, None


# ==========================================
# NORMALIZATION HELPERS
# ==========================================

_FIELD_PATTERNS = {
    "registrar": re.compile(r"^\s*registrar(?:\s+name)?\s*:\s*(.+)$", re.IGNORECASE),
    "creation_date": re.compile(
        r"^\s*(?:creation date|created(?:\s+on)?|domain registration date)\s*:\s*(.+)$",
        re.IGNORECASE,
    ),
    "updated_date": re.compile(
        r"^\s*(?:updated date|last updated on|last modified)\s*:\s*(.+)$", re.IGNORECASE
    ),
    "expiration_date": re.compile(
        r"^\s*(?:registry expiry date|expiration date|expiry date)\s*:\s*(.+)$",
        re.IGNORECASE,
    ),
    "name_server": re.compile(r"^\s*name server\s*:\s*(.+)$", re.IGNORECASE),
    "domain_status": re.compile(r"^\s*(?:domain status|status)\s*:\s*(.+)$", re.IGNORECASE),
}


def _parse_whois_text(text):
    """
    Parse raw WHOIS text into a flat dict of normalized fields.
    Multi-valued fields (name servers, statuses) are collected as lists.
    """

    parsed = {
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "name_servers": [],
        "domain_statuses": [],
    }

    for line in text.splitlines():

        for field, pattern in _FIELD_PATTERNS.items():

            match = pattern.match(line)
            if not match:
                continue

            value = match.group(1).strip()
            if not value:
                continue

            if field == "name_server":
                if value not in parsed["name_servers"]:
                    parsed["name_servers"].append(value)

            elif field == "domain_status":
                if value not in parsed["domain_statuses"]:
                    parsed["domain_statuses"].append(value)

            elif parsed.get(field) is None:
                parsed[field] = value

            break

    return parsed


def _build_domain_context(parsed):
    """Map parsed WHOIS fields onto DomainContext, packing overflow facts into dns_records."""

    dns_records = []

    if parsed["updated_date"]:
        dns_records.append(f"Updated Date: {parsed['updated_date']}")

    if parsed["expiration_date"]:
        dns_records.append(f"Expiration Date: {parsed['expiration_date']}")

    for ns in parsed["name_servers"]:
        dns_records.append(f"Name Server: {ns}")

    for status in parsed["domain_statuses"]:
        dns_records.append(f"Status: {status}")

    return DomainContext(
        registrar=parsed["registrar"],
        creation_date=parsed["creation_date"],
        dns_records=dns_records,
    )


# ==========================================
# DOMAIN
# ==========================================

def lookup_domain(domain, api_key=None):
    """Look up a domain's WHOIS registration facts.
    
    Args:
        domain: The domain name to look up.
        api_key: Unused (WHOIS requires no API key). Accepted for signature
                 compatibility with other providers.
    """

    # Preserve the original IOC value for reporting; normalize only the
    # lookup target so WHOIS servers receive the registrable domain
    # (e.g. "amazon.com") rather than a subdomain ("www.amazon.com").
    ioc = Ioc(value=domain, type=IocType.DOMAIN)
    lookup_domain = normalize_domain(domain)

    if lookup_domain != domain:
        log.debug(f"WHOIS: normalized '{domain}' → '{lookup_domain}' for lookup")

    validation_error = _validate_public_domain(lookup_domain)

    if validation_error:
        log.error(f"WHOIS lookup rejected for '{lookup_domain}' (original: '{domain}'): {validation_error}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.NOT_FOUND, error_message=validation_error,
        )

    text, err = _request(lookup_domain)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    try:
        parsed = _parse_whois_text(text)

    except Exception as e:
        log.error(f"WHOIS response parsing failed for {domain}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False, error=LookupError.PARSE_ERROR
        )

    # A syntactically valid, publicly-delegated domain whose registry
    # simply didn't return every field (e.g. WHOIS privacy redaction)
    # is still a genuine successful lookup — only the "no record at
    # all" cases above are rejected as NOT_FOUND.
    domain_context = _build_domain_context(parsed)

    result = ThreatIntelResult(ioc=ioc, domain_context=domain_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)