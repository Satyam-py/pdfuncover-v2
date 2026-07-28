# modules/threat_intel/providers/virustotal.py
"""
VirusTotal provider, migrated to the typed Threat Intelligence models.

Exposes lookup_url() / lookup_domain() / lookup_ip() / lookup_hash(),
each returning a ProviderResult. Raw VirusTotal JSON never leaves this
module — every field is normalized into ThreatIntelResult /
ReputationFinding / *Context before being returned.
"""

import base64
import os

import requests

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    ReputationFinding,
    DomainContext,
    IPContext,
    FileContext,
    UrlContext,
    LookupError,
)
from modules.threat_intel.providers.helpers import (
    make_api_key_header,
    http_get_json,
)

from modules.logging_config import get_logger
log = get_logger(__name__, "analyzer.log")

PROVIDER_NAME = "VirusTotal"

_BASE_URL = "https://www.virustotal.com/api/v3"
_TIMEOUT = 20


# ==========================================
# SHARED NORMALIZATION HELPERS
# ==========================================

def _stats(attributes):
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected + stats.get("timeout", 0)
    return malicious, suspicious, harmless, undetected, total


def _threat_names_from_results(attributes):
    """Pull distinct non-empty per-engine verdict labels, capped for readability."""

    names = []

    for engine in (attributes.get("last_analysis_results") or {}).values():
        result = engine.get("result")
        if result and result not in names:
            names.append(result)

    return names[:10]


def _categories(attributes):
    cats = attributes.get("categories", {}) or {}
    return sorted(set(cats.values()))


def _extract_registrar(whois_text):
    """Pull the registrar line out of VT's raw whois text blob, if present."""

    for line in (whois_text or "").splitlines():
        if "registrar" in line.lower() and ":" in line:
            return line.split(":", 1)[1].strip()

    return None


# ==========================================
# URL
# ==========================================

def lookup_url(url, api_key):
    """Look up a URL's VirusTotal report."""

    ioc = Ioc(value=url, type=IocType.URL)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = make_api_key_header(api_key, "x-apikey")

    data, err = http_get_json(
        f"{_BASE_URL}/urls/{url_id}", headers=headers, timeout=_TIMEOUT,
        provider_name=PROVIDER_NAME
    )
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    attributes = data.get("data", {}).get("attributes", {})
    malicious, suspicious, harmless, undetected, total = _stats(attributes)

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total=total,
        reputation=attributes.get("reputation"),
        categories=_categories(attributes),
        threat_names=attributes.get("threat_names") or _threat_names_from_results(attributes),
        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
    )

    url_context = UrlContext(
        final_url=attributes.get("last_final_url"),
        redirect_chain=attributes.get("redirection_chain", []) or [],
        http_status=attributes.get("last_http_response_code"),
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, url_context=url_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# DOMAIN
# ==========================================

def lookup_domain(domain, api_key):
    """Look up a domain's VirusTotal report."""

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    headers = make_api_key_header(api_key, "x-apikey")

    data, err = http_get_json(
        f"{_BASE_URL}/domains/{domain}", headers=headers, timeout=_TIMEOUT,
        provider_name=PROVIDER_NAME
    )
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    attributes = data.get("data", {}).get("attributes", {})
    malicious, suspicious, harmless, undetected, total = _stats(attributes)

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total=total,
        reputation=attributes.get("reputation"),
        categories=_categories(attributes),
        threat_names=_threat_names_from_results(attributes),
        permalink=f"https://www.virustotal.com/gui/domain/{domain}",
    )

    dns_records = [
        f"{rec.get('type', '?')}: {rec.get('value', '')}"
        for rec in attributes.get("last_dns_records", []) or []
    ]

    creation_date = attributes.get("creation_date")

    domain_context = DomainContext(
        registrar=_extract_registrar(attributes.get("whois", "")),
        creation_date=str(creation_date) if creation_date else None,
        dns_records=dns_records,
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, domain_context=domain_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# IP
# ==========================================

def lookup_ip(ip, api_key):
    """Look up an IP's VirusTotal report."""

    ioc = Ioc(value=ip, type=IocType.IP)

    headers = make_api_key_header(api_key, "x-apikey")

    data, err = http_get_json(
        f"{_BASE_URL}/ip_addresses/{ip}", headers=headers, timeout=_TIMEOUT,
        provider_name=PROVIDER_NAME
    )
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    attributes = data.get("data", {}).get("attributes", {})
    malicious, suspicious, harmless, undetected, total = _stats(attributes)

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total=total,
        reputation=attributes.get("reputation"),
        categories=_categories(attributes),
        threat_names=_threat_names_from_results(attributes),
        permalink=f"https://www.virustotal.com/gui/ip-address/{ip}",
    )

    ip_context = IPContext(
        asn=str(attributes.get("asn")) if attributes.get("asn") is not None else None,
        organization=attributes.get("as_owner"),
        country=attributes.get("country"),
        network=attributes.get("network"),
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, ip_context=ip_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# HASH
# ==========================================

def lookup_hash(file_hash, api_key):
    """Look up a file hash's VirusTotal report."""

    ioc = Ioc(value=file_hash, type=IocType.HASH)

    headers = make_api_key_header(api_key, "x-apikey")

    data, err = http_get_json(
        f"{_BASE_URL}/files/{file_hash}", headers=headers, timeout=_TIMEOUT,
        provider_name=PROVIDER_NAME
    )
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    attributes = data.get("data", {}).get("attributes", {})
    malicious, suspicious, harmless, undetected, total = _stats(attributes)

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total=total,
        reputation=attributes.get("reputation"),
        categories=[],
        threat_names=_threat_names_from_results(attributes),
        permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
    )

    ptc = attributes.get("popular_threat_classification", {}) or {}
    threat_category_list = ptc.get("popular_threat_category") or []

    sandbox_verdicts = [
        f"{name}: {verdict.get('category', 'unknown')}"
        for name, verdict in (attributes.get("sandbox_verdicts") or {}).items()
    ]

    last_analysis_date = attributes.get("last_analysis_date")

    file_context = FileContext(
        file_type=attributes.get("type_description") or attributes.get("magic"),
        meaningful_name=attributes.get("meaningful_name"),
        tags=attributes.get("tags", []) or [],
        threat_label=ptc.get("suggested_threat_label"),
        threat_category=threat_category_list[0].get("value") if threat_category_list else None,
        sandbox_verdicts=sandbox_verdicts,
        sigma_summary=attributes.get("sigma_analysis_stats"),
        last_analysis_date=str(last_analysis_date) if last_analysis_date else None,
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, file_context=file_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)