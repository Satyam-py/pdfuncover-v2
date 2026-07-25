# modules/threat_intel/engine.py
"""
Threat Intelligence Engine.

Single entry point for IOC enrichment. Given an Ioc, the engine
determines which registered providers support that IOC's type, calls
each one, collects the resulting ProviderResult objects, and
aggregates them into a single ThreatIntelResult via field-by-field
merging (each field is filled by whichever provider supplies it
first; already-populated fields are never overwritten).

The engine only ever consumes ProviderResult / ThreatIntelResult — it
never inspects a provider's raw response format. All providers are
now registered; adding any future provider means adding one
ProviderRegistration to PROVIDERS below — no other logic in this file
changes.
"""

import logging
import os
from typing import List, Optional

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ProviderRegistration,
    ThreatIntelResult,
    EnrichmentResult,
    LookupError,
    merge_domain_context,
    merge_ip_context,
    merge_file_context,
    merge_url_context,
)
from modules.threat_intel.providers import virustotal as vt_provider
from modules.threat_intel.providers import otx as otx_provider
from modules.threat_intel.providers import abuseipdb as abuseipdb_provider
from modules.threat_intel.providers import whois as whois_provider
from modules.threat_intel.providers import rdap as rdap_provider

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


# ==========================================
# PROVIDER REGISTRY
# ==========================================
#
# Each entry is a typed ProviderRegistration describing one provider's
# name, the IOC types it supports, its lookup_* callables per type,
# and its API key requirement. A provider need not support every
# IocType — supports() simply returns False for types it has no
# lookup for, and the engine skips it.
#
# To register a future provider: add one ProviderRegistration here.
# No other function in this file needs to change.

PROVIDERS: List[ProviderRegistration] = [
    ProviderRegistration(
        name="virustotal",
        supported_types=[IocType.URL, IocType.DOMAIN, IocType.IP, IocType.HASH],
        lookups={
            IocType.URL: vt_provider.lookup_url,
            IocType.DOMAIN: vt_provider.lookup_domain,
            IocType.IP: vt_provider.lookup_ip,
            IocType.HASH: vt_provider.lookup_hash,
        },
        requires_api_key=True,
        config_key="virustotal_api_key",
    ),
    ProviderRegistration(
        name="otx",
        supported_types=[IocType.URL, IocType.DOMAIN, IocType.IP, IocType.HASH],
        lookups={
            IocType.URL: otx_provider.lookup_url,
            IocType.DOMAIN: otx_provider.lookup_domain,
            IocType.IP: otx_provider.lookup_ip,
            IocType.HASH: otx_provider.lookup_hash,
        },
        requires_api_key=True,
        config_key="otx_api_key",
    ),
    ProviderRegistration(
        name="abuseipdb",
        supported_types=[IocType.IP],
        lookups={
            IocType.IP: abuseipdb_provider.lookup_ip,
        },
        requires_api_key=True,
        config_key="abuseipdb_api_key",
    ),
    ProviderRegistration(
        name="whois",
        supported_types=[IocType.DOMAIN],
        lookups={
            IocType.DOMAIN: whois_provider.lookup_domain,
        },
        requires_api_key=False,
        config_key=None,
    ),
    ProviderRegistration(
        name="rdap",
        supported_types=[IocType.DOMAIN, IocType.IP],
        lookups={
            IocType.DOMAIN: rdap_provider.lookup_domain,
            IocType.IP: rdap_provider.lookup_ip,
        },
        requires_api_key=False,
        config_key=None,
    ),
]


# ==========================================
# PROVIDER EXECUTION
# ==========================================

def _run_provider(
    registration: ProviderRegistration, ioc: Ioc, config: dict
) -> Optional[ProviderResult]:
    """
    Run a single registered provider against one IOC.

    Returns None if the provider doesn't support this IOC type, or is
    missing a required API key — those are "not applicable" cases, not
    lookup failures, so they're skipped rather than surfaced as errors.
    """

    if not registration.supports(ioc.type):
        return None

    api_key = None

    if registration.requires_api_key:
        api_key = config.get(registration.config_key)
        if not api_key:
            return None

    lookup_fn = registration.lookups[ioc.type]

    try:
        return lookup_fn(ioc.value, api_key) if api_key is not None else lookup_fn(ioc.value)

    except Exception as e:
        log.error(
            f"Provider '{registration.name}' raised during lookup of {ioc.value}: {e}"
        )
        return ProviderResult(
            provider=registration.name,
            ioc=ioc,
            success=False,
            error=LookupError.UNKNOWN,
            error_message=str(e),
        )


# ==========================================
# AGGREGATION (field-by-field merge)
# ==========================================

def _aggregate(ioc: Ioc, provider_results: List[ProviderResult]) -> ThreatIntelResult:
    """
    Merge every successful ProviderResult's data into one combined
    ThreatIntelResult for this IOC.

    Reputation findings are additive — one entry per provider that
    returned one (`reputations`). Context fields (domain/ip/file/url)
    are merged field-by-field across providers: e.g. WHOIS's registrar
    and RDAP's ASN and VirusTotal's categories all land in the same
    merged ThreatIntelResult, rather than only the first provider's
    context surviving.
    """

    merged = ThreatIntelResult(ioc=ioc)

    for pr in provider_results:

        if not pr.success or pr.data is None:
            continue

        data = pr.data

        if data.reputation is not None:
            merged.reputations.append(data.reputation)

        merged.domain_context = merge_domain_context(merged.domain_context, data.domain_context)
        merged.ip_context = merge_ip_context(merged.ip_context, data.ip_context)
        merged.file_context = merge_file_context(merged.file_context, data.file_context)
        merged.url_context = merge_url_context(merged.url_context, data.url_context)

    if merged.reputations:
        merged.reputation = merged.reputations[0]

    return merged


# ==========================================
# PUBLIC ENTRY POINT
# ==========================================

def enrich_ioc(ioc: Ioc, config: dict) -> EnrichmentResult:
    """
    Run every applicable provider against `ioc` and return the
    aggregated result.

    `config` holds provider credentials, e.g.:
        {"virustotal_api_key": "...", "otx_api_key": "...",
         "abuseipdb_api_key": "..."}

    Returns an EnrichmentResult:
        - result: the field-by-field aggregated ThreatIntelResult
        - provider_results: each individual provider's raw
          ProviderResult (successes and failures alike)
    """

    provider_results = []

    for registration in PROVIDERS:
        pr = _run_provider(registration, ioc, config)
        if pr is not None:
            provider_results.append(pr)

    aggregated = _aggregate(ioc, provider_results)

    return EnrichmentResult(
        ioc=ioc,
        result=aggregated,
        provider_results=provider_results,
    )