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

Raw RDAP JSON never leaves this module — every field is normalized
into ThreatIntelResult / DomainContext / IPContext before being
returned.

DomainContext has dedicated fields only for registrar and
creation_date. Registration Authority and Entity/Organization have no
dedicated field, so — following the same convention already
established by the WHOIS provider — they are appended into
DomainContext.dns_records as labeled entries.

IPContext has dedicated fields for organization, asn, country, and
network. CIDR is the primary value for `network`. Network Name,
Network Handle, and Registry have no dedicated field, and (unlike
DomainContext) IPContext has no list field to absorb overflow into —
so they are appended onto that same `network` string as a labeled
parenthetical, the closest available convention.
"""

import logging
import os

import requests

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    DomainContext,
    IPContext,
    LookupError,
)

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

PROVIDER_NAME = "RDAP"

_BOOTSTRAP_URL = "https://rdap.org"
_TIMEOUT = 20


# ==========================================
# HTTP HELPER
# ==========================================

def _request(url):
    """
    Perform a single RDAP bootstrap GET request.
    Returns (json_dict, LookupError) — exactly one of the two is None.
    """

    try:
        r = requests.get(
            url, headers={"Accept": "application/rdap+json"}, timeout=_TIMEOUT
        )

    except requests.exceptions.Timeout:
        return None, LookupError.NETWORK_ERROR

    except requests.exceptions.RequestException as e:
        log.error(f"RDAP request failed: {e}")
        return None, LookupError.NETWORK_ERROR

    if r.status_code == 404:
        return None, LookupError.NOT_FOUND

    if r.status_code in (401, 403):
        return None, LookupError.AUTH_ERROR

    if r.status_code == 429:
        return None, LookupError.RATE_LIMITED

    if r.status_code >= 400:
        return None, LookupError.UNKNOWN

    try:
        return r.json(), None

    except ValueError as e:
        log.error(f"RDAP response JSON parse failed: {e}")
        return None, LookupError.PARSE_ERROR


# ==========================================
# SHARED HELPERS
# ==========================================

def _first_present(*values):
    for v in values:
        if v:
            return v
    return None


# ==========================================
# DOMAIN NORMALIZATION (IETF RDAP domain schema)
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
# IP NORMALIZATION (RIR-style RDAP network schema)
# ==========================================

def _extract_organization(data, network):
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
    return _first_present(
        network.get("cidr"),
        data.get("asn_cidr"),
        network.get("cidr0_cidrs", [{}])[0].get("v4prefix")
        if network.get("cidr0_cidrs") else None,
    )


def _build_ip_context(data):
    network = data.get("network") or {}

    organization = _extract_organization(data, network)
    asn = _first_present(data.get("asn"), str(data.get("autnums")) if data.get("autnums") else None)
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
    """Look up a domain's RDAP registration facts."""

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    data, err = _request(f"{_BOOTSTRAP_URL}/domain/{domain}")
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
# IP
# ==========================================

def lookup_ip(ip):
    """Look up an IP's RDAP network/organization facts."""

    ioc = Ioc(value=ip, type=IocType.IP)

    data, err = _request(f"{_BOOTSTRAP_URL}/ip/{ip}")
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    try:
        ip_context = _build_ip_context(data)

    except Exception as e:
        log.error(f"RDAP IP response parsing failed for {ip}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False, error=LookupError.PARSE_ERROR
        )

    result = ThreatIntelResult(ioc=ioc, ip_context=ip_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)