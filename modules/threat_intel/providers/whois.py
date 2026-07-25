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
"""

import logging
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

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

PROVIDER_NAME = "WHOIS"

_IANA_WHOIS_SERVER = "whois.iana.org"
_WHOIS_PORT = 43
_TIMEOUT = 10
_MAX_RESPONSE_BYTES = 65536


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


def _request(domain):
    """
    Resolve the authoritative WHOIS server via IANA, then query it.
    Returns (raw_text, LookupError) — exactly one of the two is None.
    """

    try:
        iana_text = _query_server(_IANA_WHOIS_SERVER, domain)

    except socket.timeout:
        return None, LookupError.NETWORK_ERROR

    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        log.error(f"WHOIS IANA referral lookup failed for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR

    referral = _find_referral(iana_text)
    text = iana_text

    if referral and referral.lower() != _IANA_WHOIS_SERVER:

        try:
            text = _query_server(referral, domain)

        except socket.timeout:
            return None, LookupError.NETWORK_ERROR

        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            log.error(f"WHOIS registry lookup failed for {domain} via {referral}: {e}")
            return None, LookupError.NETWORK_ERROR

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

def lookup_domain(domain):
    """Look up a domain's WHOIS registration facts."""

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    text, err = _request(domain)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    try:
        parsed = _parse_whois_text(text)

    except Exception as e:
        log.error(f"WHOIS response parsing failed for {domain}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False, error=LookupError.PARSE_ERROR
        )

    # No registration data found for an otherwise-valid domain — this
    # is not an error, just an empty (but successful) DomainContext.
    domain_context = _build_domain_context(parsed)

    result = ThreatIntelResult(ioc=ioc, domain_context=domain_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)