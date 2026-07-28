# modules/threat_intel/providers/rdap.py
"""
RDAP provider, following the same conventions as the existing
providers (VirusTotal, OTX, URLScan, AbuseIPDB, WHOIS).

RDAP is a Context Provider — like WHOIS, it never determines whether
an indicator is malicious, it only reports registration/network facts.
Accordingly this provider returns only DomainContext / IPContext,
never a ReputationFinding.

Only lookup_domain() and lookup_ip() are implemented; RDAP supports
domains and IPs only, so no stub methods exist for URL/Hash —
unsupported types are expressed purely through
ProviderRegistration.supported_types.

DOMAIN LOOKUPS (unchanged): raw RDAP JSON is fetched directly from the
rdap.org bootstrap service via `requests` and normalized by hand, same
as before. DomainContext has dedicated fields only for registrar and
creation_date; Registration Authority and Entity/Organization have no
dedicated field, so — following the same convention already
established by the WHOIS provider — they are appended into
DomainContext.dns_records as labeled entries.

IP LOOKUPS (migrated to `ipwhois`): this provider no longer issues its
own bootstrap HTTP request for IPs. It now uses the `ipwhois` library
(IPWhois(ip).lookup_rdap()), which already handles RDAP bootstrap
resolution, redirects/referrals, retries, and response parsing
internally — the manual HTTP + status-code handling this module used
to do for IPs is no longer needed and has been removed. Only the
mapping from ipwhois's already-parsed result dict onto this codebase's
IPContext model remains here.

IPContext has dedicated fields for organization, asn, country, and
network. CIDR is the primary value for `network`. Network Name and
Network Handle have no dedicated field, so they are appended onto that
same `network` string as a labeled parenthetical, the closest
available convention (unchanged from the previous implementation).

Raw RDAP/ipwhois data never leaves this module — every field is
normalized into ThreatIntelResult / DomainContext / IPContext before
being returned.
"""


import os

import requests

from ipwhois import IPWhois
from ipwhois.exceptions import (
    IPDefinedError,
    ASNRegistryError,
    ASNParseError,
    ASNLookupError,
    HTTPLookupError,
    HTTPRateLimitError,
    WhoisLookupError,
    WhoisRateLimitError,
    RDAPLookupError,
)

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    DomainContext,
    IPContext,
    LookupError,
)
from modules.threat_intel.providers.helpers import http_get_json
# logging is configured in modules/logging_config.py, not here
from modules.logging_config import get_logger
log = get_logger(__name__, "analyzer.log")

PROVIDER_NAME = "RDAP"

_BOOTSTRAP_URL = "https://rdap.org"
_TIMEOUT = 20


# ==========================================
# SHARED HELPERS
# ==========================================

def _first_present(*values):
    for v in values:
        if v:
            return v
    return None


# ==========================================
# DOMAIN NORMALIZATION (IETF RDAP domain schema) — unchanged
# ==========================================

def _vcard_fn(vcard_array):
    """Pull the 'fn' (formatted name) property out of a jCard vcard_array."""

    if not vcard_array or len(vcard_array) < 2:
        return None

    for prop in vcard_array[1]:
        if prop and prop[0] == "fn":
            values = prop[3] if len(prop) > 3 else None
            if isinstance(values, list):
                return values[0] if values else None
            return values

    return None


def _find_entity_by_role(entities, role):
    for entity in entities or []:
        if role in (entity.get("roles") or []):
            return entity
    return None


def _registrar_iana_id(registrar_entity):
    if not registrar_entity:
        return None

    for pub_id in registrar_entity.get("public_ids") or []:
        if pub_id.get("type") == "IANA Registrar ID":
            return pub_id.get("identifier")

    return None


def _find_event_date(events, action):
    for event in events or []:
        if (event.get("event_action") or "").lower() == action:
            return event.get("event_date")
    return None


def _build_domain_context(data):
    entities = data.get("entities") or []

    registrar_entity = _find_entity_by_role(entities, "registrar")
    registrant_entity = _find_entity_by_role(entities, "registrant")

    registrar_name = _vcard_fn(registrar_entity.get("vcard_array")) if registrar_entity else None
    organization_name = (
        _vcard_fn(registrant_entity.get("vcard_array")) if registrant_entity else None
    )

    registration_date = _find_event_date(data.get("events"), "registration")
    iana_id = _registrar_iana_id(registrar_entity)

    dns_records = []

    if iana_id:
        dns_records.append(f"Registration Authority: IANA Registrar ID {iana_id}")

    if organization_name:
        dns_records.append(f"Organization: {organization_name}")

    return DomainContext(
        registrar=registrar_name,
        creation_date=registration_date,
        dns_records=dns_records,
    )


# ==========================================
# IP NORMALIZATION (ipwhois-backed)
# ==========================================
#
# IPWhois(ip).lookup_rdap() already resolves the correct RIR, follows
# referrals, and returns a fully-parsed dict — this only maps that
# dict's fields onto IPContext. Shape (top-level 'asn'/'asn_cidr'/
# 'asn_country_code'/'asn_description'/'asn_registry' plus a nested
# 'network' dict, 'entities' list, and 'objects' dict keyed by entity
# handle) mirrors the raw IETF RDAP network schema this module already
# understood, so the extraction logic below is intentionally close to
# the previous bootstrap-based version — only the fields ipwhois
# doesn't provide (e.g. the old 'autnums' / 'cidr0_cidrs' bootstrap-
# specific fallbacks) have been dropped as unnecessary.

def _extract_organization(data, network):
    """
    Prefer a contact name from one of the RDAP entities ipwhois already
    parsed into data['objects']; fall back to the network's own name or
    the ASN's description line.
    """

    objects = data.get("objects") or {}
    entity_ids = data.get("entities") or []

    for entity_id in entity_ids:
        entity = objects.get(entity_id) or {}
        contact = entity.get("contact") or {}
        name = contact.get("name")
        if name:
            return name

    return _first_present(network.get("name"), data.get("asn_description"))


def _extract_cidr(data, network):
    """CIDR from the network block, falling back to the ASN-level CIDR
    ipwhois also surfaces at the top level."""

    return _first_present(network.get("cidr"), data.get("asn_cidr"))


def _build_ip_context(data):
    network = data.get("network") or {}

    organization = _extract_organization(data, network)
    asn = _first_present(data.get("asn"), data.get("asn_description"))
    country = _first_present(network.get("country"), data.get("asn_country_code"))
    registry = data.get("asn_registry")

    cidr = _extract_cidr(data, network)
    net_name = network.get("name")
    net_handle = network.get("handle")

    extras = []
    if net_name:
        extras.append(f"Name: {net_name}")
    if net_handle:
        extras.append(f"Handle: {net_handle}")
    if registry:
        extras.append(f"Registry: {registry}")

    if cidr and extras:
        network_field = f"{cidr} ({', '.join(extras)})"
    elif cidr:
        network_field = cidr
    elif extras:
        network_field = ", ".join(extras)
    else:
        network_field = None

    return IPContext(
        asn=asn,
        organization=organization,
        country=country,
        network=network_field,
    )


# ==========================================
# DOMAIN
# ==========================================

def lookup_domain(domain):
    """Look up a domain's RDAP registration facts. Unchanged: still
    queries the rdap.org bootstrap service directly via `requests`."""

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    headers = {"Accept": "application/rdap+json"}
    data, err = http_get_json(
        f"{_BOOTSTRAP_URL}/domain/{domain}", headers=headers, timeout=_TIMEOUT,
        provider_name=PROVIDER_NAME
    )
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    try:
        domain_context = _build_domain_context(data)

    except Exception as e:
        log.error(f"RDAP domain response parsing failed for {domain}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False, error=LookupError.PARSE_ERROR
        )

    result = ThreatIntelResult(ioc=ioc, domain_context=domain_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# IP (now backed by the ipwhois library)
# ==========================================

def lookup_ip(ip):
    """
    Look up an IP's RDAP network/organization facts via the `ipwhois`
    library instead of a hand-rolled RDAP bootstrap request.

    Signature is unchanged (single `ip` positional argument, no API
    key — RDAP/ipwhois needs none) so the ProviderRegistration in
    modules/threat_intel/engine.py and every existing call site keep
    working without modification.
    """

    ioc = Ioc(value=ip, type=IocType.IP)

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)

    except IPDefinedError as e:
        # Private/reserved/special-use address (RFC 1918, loopback,
        # link-local, etc.) — there is no public RDAP record to find,
        # which is a "not found" outcome rather than a lookup failure.
        log.error(f"RDAP IP lookup skipped for {ip} (private/reserved address): {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.NOT_FOUND, error_message=str(e),
        )

    except (HTTPRateLimitError, WhoisRateLimitError) as e:
        log.error(f"RDAP IP lookup rate-limited for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.RATE_LIMITED, error_message=str(e),
        )

    except (HTTPLookupError, WhoisLookupError, ASNLookupError) as e:
        log.error(f"RDAP IP network lookup failed for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.NETWORK_ERROR, error_message=str(e),
        )

    except (ASNRegistryError, ASNParseError, RDAPLookupError) as e:
        log.error(f"RDAP IP lookup/parse failed for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.PARSE_ERROR, error_message=str(e),
        )

    except Exception as e:
        # Anything ipwhois itself doesn't classify (unexpected/library
        # internal errors) — never let one bad lookup take down the
        # rest of enrichment.
        log.error(f"Unexpected RDAP IP lookup error for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.UNKNOWN, error_message=str(e),
        )

    try:
        ip_context = _build_ip_context(result)

    except Exception as e:
        log.error(f"RDAP IP response parsing failed for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False,
            error=LookupError.PARSE_ERROR, error_message=str(e),
        )

    threat_intel_result = ThreatIntelResult(ioc=ioc, ip_context=ip_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=threat_intel_result)