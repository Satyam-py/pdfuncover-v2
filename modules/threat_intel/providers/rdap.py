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

DOMAIN LOOKUPS: Query registry RDAP endpoints directly for known TLDs
(COM, NET via VeriSign; ORG via PRIR) or use ARIN bootstrap for others.
DomainContext has dedicated fields only for registrar and creation_date;
additional domain info (organization, expiration date, status, nameservers,
DNSSEC, abuse contact, domain age) is appended into DomainContext.dns_records
as labeled entries, following the same convention as the WHOIS provider.

IP LOOKUPS (ipwhois-backed): Uses the `ipwhois` library which handles RDAP
bootstrap resolution, redirects/referrals, retries, and response parsing
internally. Only mapping from ipwhois's parsed result dict onto IPContext.

Raw RDAP data never leaves this module — every field is normalized into
ThreatIntelResult / DomainContext / IPContext before being returned.
"""


import os
from datetime import datetime

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
from modules.threat_intel.providers.helpers import http_get_json, normalize_domain
# logging is configured in modules/logging_config.py, not here
from modules.logging_config import get_logger
log = get_logger(__name__, "analyzer.log")

PROVIDER_NAME = "RDAP"

_BOOTSTRAP_URL = "https://rdap-bootstrap.arin.net/bootstrap/domain"
_TIMEOUT = 20

# Direct registry RDAP endpoints for known TLDs
_REGISTRY_ENDPOINTS = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
}


# ==========================================
# SHARED HELPERS
# ==========================================

def _first_present(*values):
    for v in values:
        if v:
            return v
    return None


def _get_tld(domain):
    """Extract TLD from domain name (last label)."""
    if not domain:
        return None
    labels = domain.lower().strip(".").split(".")
    return labels[-1] if labels else None


def _calculate_domain_age(creation_date_str):
    """Calculate domain age in days from ISO 8601 date string."""
    if not creation_date_str:
        return None
    try:
        # Handle ISO 8601 format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, etc.)
        if "T" in creation_date_str:
            creation_date = datetime.fromisoformat(
                creation_date_str.replace("Z", "+00:00").split("+")[0]
            )
        else:
            creation_date = datetime.fromisoformat(creation_date_str)
        age = (datetime.now() - creation_date).days
        return max(0, age)
    except Exception:
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


def _extract_abuse_contact(entities):
    """Extract abuse contact email and phone from entities."""
    email = None
    phone = None
    
    for entity in entities or []:
        if "abuse" in (entity.get("roles") or []):
            vcard = entity.get("vcard_array")
            if vcard and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop and len(prop) > 0:
                        if prop[0] == "email" and len(prop) > 3:
                            values = prop[3] if isinstance(prop[3], list) else [prop[3]]
                            if values:
                                email = values[0]
                        elif prop[0] == "tel" and len(prop) > 3:
                            values = prop[3] if isinstance(prop[3], list) else [prop[3]]
                            if values:
                                phone = values[0]
    
    return email, phone


def _extract_nameservers(rdap_data):
    """Extract nameservers from RDAP response."""
    nameservers = []
    
    # Check for nameserver objects (if present)
    if "nameservers" in rdap_data:
        for ns in rdap_data.get("nameservers", []):
            if "ldhName" in ns:
                nameservers.append(ns["ldhName"])
            elif "unicodeName" in ns:
                nameservers.append(ns["unicodeName"])
    
    return nameservers


def _extract_statuses(rdap_data):
    """Extract domain statuses from RDAP response."""
    statuses = []
    
    for status in rdap_data.get("status", []):
        statuses.append(status)
    
    return statuses


def _check_dnssec(rdap_data):
    """Check if DNSSEC is present in RDAP response."""
    if "secureDNS" in rdap_data:
        secure_dns = rdap_data["secureDNS"]
        if isinstance(secure_dns, dict):
            return secure_dns.get("delegationSigned", False)
    return False


def _get_rdap_server_url(rdap_data):
    """Extract RDAP server URL from response."""
    notices = rdap_data.get("notices", [])
    for notice in notices:
        if "links" in notice:
            for link in notice["links"]:
                if link.get("rel") == "self":
                    return link.get("href")
    # Fallback: use rdap object url if available
    return rdap_data.get("port43")


def _build_domain_context(data):
    entities = data.get("entities") or []

    registrar_entity = _find_entity_by_role(entities, "registrar")
    registrant_entity = _find_entity_by_role(entities, "registrant")

    registrar_name = _vcard_fn(registrar_entity.get("vcard_array")) if registrar_entity else None
    organization_name = (
        _vcard_fn(registrant_entity.get("vcard_array")) if registrant_entity else None
    )

    registration_date = _find_event_date(data.get("events"), "registration")
    expiration_date = _find_event_date(data.get("events"), "expiration")
    last_updated_date = _find_event_date(data.get("events"), "last changed")
    iana_id = _registrar_iana_id(registrar_entity)
    
    # Extract abuse contact
    abuse_email, abuse_phone = _extract_abuse_contact(entities)
    
    # Extract additional domain information
    nameservers = _extract_nameservers(data)
    statuses = _extract_statuses(data)
    dnssec_enabled = _check_dnssec(data)
    rdap_server = _get_rdap_server_url(data)
    domain_age = _calculate_domain_age(registration_date)

    dns_records = []

    if iana_id:
        dns_records.append(f"Registrar IANA ID: {iana_id}")

    if organization_name:
        dns_records.append(f"Organization: {organization_name}")
    
    if expiration_date:
        dns_records.append(f"Expiration Date: {expiration_date}")
    
    if last_updated_date:
        dns_records.append(f"Last Updated: {last_updated_date}")
    
    if domain_age is not None:
        dns_records.append(f"Domain Age: {domain_age} days")
    
    if statuses:
        for status in statuses:
            dns_records.append(f"Status: {status}")
    
    if nameservers:
        for ns in nameservers:
            dns_records.append(f"Nameserver: {ns}")
    
    if dnssec_enabled:
        dns_records.append("DNSSEC: Enabled")
    
    if abuse_email:
        dns_records.append(f"Abuse Email: {abuse_email}")
    
    if abuse_phone:
        dns_records.append(f"Abuse Phone: {abuse_phone}")
    
    if rdap_server:
        dns_records.append(f"RDAP Server: {rdap_server}")

    return DomainContext(
        registrar=registrar_name,
        creation_date=registration_date,
        dns_records=dns_records,
    )


# ==========================================
# DOMAIN LOOKUP
# ==========================================

def _get_registry_rdap_url(domain):
    """
    Get the appropriate RDAP endpoint URL for a domain.
    Returns (url, is_direct) where is_direct indicates if it's a direct registry
    endpoint (True) or needs bootstrap (False).
    """
    tld = _get_tld(domain)
    
    if tld and tld.lower() in _REGISTRY_ENDPOINTS:
        # Direct registry endpoint
        return _REGISTRY_ENDPOINTS[tld.lower()] + domain, True
    else:
        # Use bootstrap for unknown TLDs
        return f"{_BOOTSTRAP_URL}/{domain}", False


def _query_rdap_domain(domain):
    """
    Query RDAP for domain information.
    Tries direct registry endpoint first for known TLDs, then bootstrap as fallback.
    Returns (data_dict, error_code) where exactly one is None.
    """
    url, is_direct = _get_registry_rdap_url(domain)
    headers = {"Accept": "application/rdap+json"}
    
    # Try the primary endpoint
    try:
        response = requests.get(url, headers=headers, timeout=_TIMEOUT)
        
        if response.status_code == 404:
            log.error(f"RDAP domain not found: {domain}")
            return None, LookupError.NOT_FOUND
        elif response.status_code == 429:
            log.error(f"RDAP rate limited for {domain}")
            return None, LookupError.RATE_LIMITED
        elif response.status_code == 403:
            # 403 is treated as network error, not auth error
            log.error(f"RDAP access forbidden for {domain}")
            return None, LookupError.NETWORK_ERROR
        elif response.status_code >= 500:
            log.error(f"RDAP server error for {domain}: HTTP {response.status_code}")
            return None, LookupError.NETWORK_ERROR
        elif response.status_code >= 400:
            log.error(f"RDAP client error for {domain}: HTTP {response.status_code}")
            return None, LookupError.NETWORK_ERROR
        
        # Success
        try:
            data = response.json()
            return data, None
        except Exception as e:
            log.error(f"Failed to parse RDAP JSON response for {domain}: {e}")
            return None, LookupError.PARSE_ERROR
    
    except requests.Timeout:
        log.error(f"RDAP lookup timeout for {domain}")
        return None, LookupError.NETWORK_ERROR
    except requests.ConnectionError as e:
        log.error(f"RDAP connection error for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR
    except Exception as e:
        log.error(f"RDAP lookup error for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR


def _query_rdap_domain_with_bootstrap_fallback(domain):
    """
    Query RDAP for domain, with bootstrap fallback for direct registry endpoints.
    First tries direct registry endpoint if available, then falls back to bootstrap.
    """
    tld = _get_tld(domain)
    
    # If we have a direct registry endpoint, try it first
    if tld and tld.lower() in _REGISTRY_ENDPOINTS:
        url = _REGISTRY_ENDPOINTS[tld.lower()] + domain
        headers = {"Accept": "application/rdap+json"}
        
        try:
            response = requests.get(url, headers=headers, timeout=_TIMEOUT)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return data, None
                except Exception as e:
                    log.error(f"Failed to parse RDAP JSON for {domain}: {e}")
                    return None, LookupError.PARSE_ERROR
            elif response.status_code == 404:
                log.error(f"RDAP domain not found: {domain}")
                return None, LookupError.NOT_FOUND
            elif response.status_code == 429:
                log.error(f"RDAP rate limited for {domain}")
                return None, LookupError.RATE_LIMITED
            elif response.status_code == 403:
                log.error(f"RDAP access forbidden for {domain}")
                return None, LookupError.NETWORK_ERROR
            elif response.status_code >= 500:
                # Server error, fallback to bootstrap
                log.debug(f"Direct RDAP registry error for {domain}, trying bootstrap")
            else:
                # Other error, fallback to bootstrap
                log.debug(f"Direct RDAP query failed for {domain}, trying bootstrap")
        
        except (requests.Timeout, requests.ConnectionError) as e:
            log.debug(f"Direct RDAP connection failed for {domain}, trying bootstrap")
        except Exception as e:
            log.debug(f"Direct RDAP lookup error for {domain}, trying bootstrap: {e}")
    
    # Fallback to bootstrap endpoint
    url = f"{_BOOTSTRAP_URL}/{domain}"
    headers = {"Accept": "application/rdap+json"}
    
    try:
        response = requests.get(url, headers=headers, timeout=_TIMEOUT)
        
        if response.status_code == 200:
            try:
                data = response.json()
                return data, None
            except Exception as e:
                log.error(f"Failed to parse bootstrap RDAP JSON for {domain}: {e}")
                return None, LookupError.PARSE_ERROR
        elif response.status_code == 404:
            log.error(f"RDAP bootstrap: domain not found {domain}")
            return None, LookupError.NOT_FOUND
        elif response.status_code == 429:
            log.error(f"RDAP bootstrap: rate limited for {domain}")
            return None, LookupError.RATE_LIMITED
        elif response.status_code >= 400:
            log.error(f"RDAP bootstrap error for {domain}: HTTP {response.status_code}")
            return None, LookupError.NETWORK_ERROR
        
    except requests.Timeout:
        log.error(f"RDAP bootstrap timeout for {domain}")
        return None, LookupError.NETWORK_ERROR
    except requests.ConnectionError as e:
        log.error(f"RDAP bootstrap connection error for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR
    except Exception as e:
        log.error(f"RDAP bootstrap error for {domain}: {e}")
        return None, LookupError.NETWORK_ERROR
    
    return None, LookupError.NETWORK_ERROR


def lookup_domain(domain, api_key=None):
    """Look up a domain's RDAP registration facts.
    
    Args:
        domain: The domain name to look up.
        api_key: Unused (RDAP requires no API key). Accepted for signature
                 compatibility with other providers.
    
    Returns:
        ProviderResult with DomainContext on success, or appropriate error.
    """

    # Preserve the original IOC value for reporting; normalize only the
    # lookup target so RDAP endpoints receive the registrable domain
    # (e.g. "amazon.com") rather than a subdomain ("www.amazon.com").
    ioc = Ioc(value=domain, type=IocType.DOMAIN)
    lookup_target = normalize_domain(domain)

    if lookup_target != domain:
        log.debug(f"RDAP: normalized '{domain}' → '{lookup_target}' for lookup")

    try:
        data, err = _query_rdap_domain_with_bootstrap_fallback(lookup_target)
        
        if err:
            return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

        domain_context = _build_domain_context(data)

    except Exception as e:
        log.error(f"RDAP domain response parsing failed for {domain}: {e}")
        return ProviderResult(
            provider=PROVIDER_NAME, ioc=ioc, success=False, error=LookupError.PARSE_ERROR
        )

    result = ThreatIntelResult(ioc=ioc, domain_context=domain_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# IP (ipwhois-backed)
# ==========================================

def lookup_ip(ip, api_key=None):
    """
    Look up an IP's RDAP network/organization facts via the `ipwhois`
    library instead of a hand-rolled RDAP bootstrap request.

    Args:
        ip: The IP address to look up.
        api_key: Unused (RDAP requires no API key). Accepted for signature
                 compatibility with other providers.
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

    except (ASNRegistryError, ASNParseError) as e:
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


# ==========================================
# IP NORMALIZATION (ipwhois-backed)
# ==========================================

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