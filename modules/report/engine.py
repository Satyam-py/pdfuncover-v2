# modules/threat_intel/engine.py
"""
Threat Intelligence Engine — frozen provider orchestration layer.

This module serves as the central orchestration point for all Threat
Intelligence providers (VirusTotal, OTX, URLScan, AbuseIPDB, WHOIS, RDAP).
It is called ONLY from modules/threat_intel_pipeline.py's enrich_ioc(),
and ONLY to perform IOC enrichment — no detection logic, no scoring,
just provider execution and result aggregation.

The engine is FROZEN per Step 9 requirements:
  - Provider registry (PROVIDERS) is defined here and never modified
    after Step 9.
  - No new providers are added after this file is created.
  - No detection or filtering logic is added here.
  - It performs only: provider dispatch, result aggregation, and
    field-by-field context merging per modules/threat_intel/models.py

Provider Selection:
  - enrich_ioc() looks up ioc.type in PROVIDERS
  - For each provider that supports ioc.type, the corresponding lookup
    function is called with (ioc.value, api_key)
  - Providers requiring an API key are skipped if the key is missing
  - Providers without an API key (WHOIS, RDAP context providers) always run

Result Aggregation:
  - Every ProviderResult (success or failure) is preserved in the
    provider_results list for per-provider detail visibility.
  - Successful results are aggregated into a single ThreatIntelResult:
    * ReputationFindings are accumulated in result.reputations[]
    * Context objects (IP, Domain, URL, File) are merged per provider
      order of appearance, with existing fields preserved and missing
      fields filled in from new providers.
  - Returns EnrichmentResult(ioc, result, provider_results)

Import Note:
  This module imports directly from provider modules (virustotal, otx,
  urlscan, abuseipdb, whois, rdap), not from their subpackages. Files
  in the actual deployment will be in modules/threat_intel/providers/*.py.
  Imports are adjusted here to match the flat file structure during
  development.
"""

import logging
import os
from typing import Any, Dict, List, Optional

# Imports from the TI models and provider modules
from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    ReputationFinding,
    EnrichmentResult,
    DomainContext,
    IPContext,
    FileContext,
    UrlContext,
    LookupError,
    merge_ip_context,
    merge_domain_context,
    merge_file_context,
    merge_url_context,
    ProviderRegistration,
)

from modules.threat_intel.providers import (
    virustotal,
    otx,
    urlscan,
    abuseipdb,
    whois,
    rdap,
)


# ==========================================
# LOGGING SETUP
# ==========================================

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
# FROZEN per Step 9: this registry is defined once here and never
# modified. No new providers are added after this point. Each
# ProviderRegistration specifies:
#   - name: human-readable provider name
#   - supported_types: IOC types this provider handles (URL/Domain/IP/Hash)
#   - lookups: dict mapping IocType -> lookup function
#   - requires_api_key: whether an API key is mandatory
#   - config_key: env var / config file key for the API key (if required)

PROVIDERS: List[ProviderRegistration] = [
    # ========================
    # REPUTATION PROVIDERS
    # ========================
    # These return actual malice/suspicious/harmless vote counts and
    # contribute to the final verdict score.
    
    ProviderRegistration(
        name="VirusTotal",
        supported_types=[IocType.URL, IocType.DOMAIN, IocType.IP, IocType.HASH],
        lookups={
            IocType.URL: virustotal.lookup_url,
            IocType.DOMAIN: virustotal.lookup_domain,
            IocType.IP: virustotal.lookup_ip,
            IocType.HASH: virustotal.lookup_hash,
        },
        requires_api_key=True,
        config_key="virustotal_api_key",
    ),
    
    ProviderRegistration(
        name="OTX",
        supported_types=[IocType.URL, IocType.DOMAIN, IocType.IP, IocType.HASH],
        lookups={
            IocType.URL: otx.lookup_url,
            IocType.DOMAIN: otx.lookup_domain,
            IocType.IP: otx.lookup_ip,
            IocType.HASH: otx.lookup_hash,
        },
        requires_api_key=True,
        config_key="otx_api_key",
    ),
    
    ProviderRegistration(
        name="URLScan",
        supported_types=[IocType.URL, IocType.DOMAIN, IocType.IP],
        lookups={
            IocType.URL: urlscan.lookup_url,
            IocType.DOMAIN: urlscan.lookup_domain,
            IocType.IP: urlscan.lookup_ip,
        },
        requires_api_key=False,  # URLScan allows unauthenticated searches
        config_key=None,
    ),
    
    ProviderRegistration(
        name="AbuseIPDB",
        supported_types=[IocType.IP],
        lookups={
            IocType.IP: abuseipdb.lookup_ip,
        },
        requires_api_key=True,
        config_key="abuseipdb_api_key",
    ),
    
    # ========================
    # CONTEXT PROVIDERS
    # ========================
    # These do not return reputation verdicts, only enrichment context
    # (registrar, ASN, etc.). They contribute to the EnrichmentResult
    # but not to the verdict score.
    
    ProviderRegistration(
        name="WHOIS",
        supported_types=[IocType.DOMAIN],
        lookups={
            IocType.DOMAIN: whois.lookup_domain,
        },
        requires_api_key=False,
        config_key=None,
    ),
    
    ProviderRegistration(
        name="RDAP",
        supported_types=[IocType.DOMAIN, IocType.IP],
        lookups={
            IocType.DOMAIN: rdap.lookup_domain,
            IocType.IP: rdap.lookup_ip,
        },
        requires_api_key=False,
        config_key=None,
    ),
]


# ==========================================
# AGGREGATION HELPERS
# ==========================================

def _merge_reputation_findings(findings: List[ReputationFinding]) -> List[ReputationFinding]:
    """
    Collect all successful ReputationFindings into the result's
    reputations[] field. No deduplication or filtering — every
    successful reputation provider's result is preserved.
    """
    return findings


def _aggregate_result(
    ioc: Ioc, provider_results: List[ProviderResult]
) -> ThreatIntelResult:
    """
    Aggregate all ProviderResults (successful and failed) into a
    single ThreatIntelResult by merging fields from successful lookups.
    
    Successful results contribute:
      - Their ReputationFinding to result.reputations[]
      - Their context (IP, Domain, URL, File) merged into result.*_context
    
    Failed results are simply preserved in provider_results for
    per-provider visibility but do not affect the aggregated result.
    """

    reputations: List[ReputationFinding] = []
    ip_context: Optional[IPContext] = None
    domain_context: Optional[DomainContext] = None
    url_context: Optional[UrlContext] = None
    file_context: Optional[FileContext] = None

    for pr in provider_results:
        if not pr.success or pr.data is None:
            continue

        # Collect reputation findings from successful lookups
        if pr.data.reputation is not None:
            reputations.append(pr.data.reputation)

        # Merge context objects (existing fields preserved, new fields filled in)
        ip_context = merge_ip_context(ip_context, pr.data.ip_context)
        domain_context = merge_domain_context(domain_context, pr.data.domain_context)
        url_context = merge_url_context(url_context, pr.data.url_context)
        file_context = merge_file_context(file_context, pr.data.file_context)

    return ThreatIntelResult(
        ioc=ioc,
        reputation=None,  # Legacy field; reputations[] is the new interface
        reputations=reputations,
        ip_context=ip_context,
        domain_context=domain_context,
        url_context=url_context,
        file_context=file_context,
    )


# ==========================================
# PROVIDER EXECUTION (with RDAP-first/WHOIS-fallback for domains)
# ==========================================

def _run_provider(provider_reg: ProviderRegistration, ioc: Ioc, config: Dict[str, Any]) -> Optional[ProviderResult]:
    """
    Execute a single provider and return its ProviderResult, or None if skipped.
    """
    # Skip if this provider doesn't support this IOC type
    if not provider_reg.supports(ioc.type):
        return None

    # Skip if this provider requires an API key and we don't have it
    if provider_reg.requires_api_key:
        api_key = config.get(provider_reg.config_key)
        if not api_key:
            log.warning(
                f"Skipping {provider_reg.name}: no API key configured "
                f"({provider_reg.config_key})"
            )
            return None
    else:
        api_key = None

    # Execute the provider lookup
    try:
        lookup_fn = provider_reg.lookups[ioc.type]
        result = lookup_fn(ioc.value, api_key)
        return result

    except Exception as e:
        log.error(
            f"Exception calling {provider_reg.name}.lookup_{ioc.type.value}(): {e}"
        )
        # Create a failed result to preserve the error in the output
        return ProviderResult(
            provider=provider_reg.name,
            ioc=ioc,
            success=False,
            error=None,
            error_message=str(e),
        )


def _should_run_whois_fallback(rdap_result: Optional[ProviderResult]) -> bool:
    """
    Determine if WHOIS should run as a fallback after RDAP for domain lookups.
    
    WHOIS runs if RDAP:
    - Did not run (None)
    - Failed with NOT_FOUND, NETWORK_ERROR, PARSE_ERROR, or RATE_LIMITED
    - Succeeded but returned empty/minimal context (no meaningful data)
    
    WHOIS does NOT run if RDAP already returned valid context.
    """
    if rdap_result is None:
        return True
    
    # WHOIS fallback for these error types
    if not rdap_result.success:
        if rdap_result.error in (
            LookupError.NOT_FOUND,
            LookupError.NETWORK_ERROR,
            LookupError.PARSE_ERROR,
            LookupError.RATE_LIMITED,
        ):
            log.info(f"[WHOIS] Running fallback lookup (RDAP error: {rdap_result.error.value})")
            return True
        # Don't fallback for AUTH_ERROR or UNKNOWN
        return False
    
    # RDAP succeeded - check if it returned meaningful context
    if rdap_result.data is None or rdap_result.data.domain_context is None:
        log.info("[WHOIS] Running fallback lookup (RDAP returned no domain context)")
        return True
    
    # RDAP returned valid context - skip WHOIS
    log.info("[WHOIS] Skipped (RDAP succeeded with valid context)")
    return False


def enrich_ioc(ioc: Ioc, config: Dict[str, Any]) -> EnrichmentResult:
    """
    Enrich one IOC by dispatching it to providers.
    
    Special handling for domains:
    - RDAP is the PRIMARY provider (always runs first)
    - WHOIS is the FALLBACK (only runs if RDAP fails/returns minimal data)
    
    For all other IOC types, providers run in standard registry order.

    Args:
        ioc: The (type, value) pair to enrich.
        config: {config_key: api_key} dict as built by app_config.get_provider_config().
                Missing keys mean no API key is available for that provider.

    Returns:
        EnrichmentResult with:
          - ioc: the input ioc
          - result: aggregated ThreatIntelResult (reputations[], contexts)
          - provider_results: full list of individual provider outcomes

    Never raises. Providers that fail, timeout, or have no API key
    simply produce a failed ProviderResult which is preserved but not
    aggregated into result.
    """

    provider_results: List[ProviderResult] = []

    # Special handling for domain IOCs: RDAP first, then WHOIS fallback
    if ioc.type == IocType.DOMAIN:
        rdap_result = None
        
        # Step 1: Run RDAP (primary provider for domains)
        for provider_reg in PROVIDERS:
            if provider_reg.name == "RDAP":
                rdap_result = _run_provider(provider_reg, ioc, config)
                if rdap_result:
                    log.info("[RDAP] Lookup executed")
                    provider_results.append(rdap_result)
                    if rdap_result.success:
                        log.info("[RDAP] Lookup successful")
                    else:
                        log.info(f"[RDAP] Failed: {rdap_result.error.value if rdap_result.error else 'unknown'}")
                break
        
        # Step 2: Run WHOIS as fallback (if appropriate)
        if _should_run_whois_fallback(rdap_result):
            for provider_reg in PROVIDERS:
                if provider_reg.name == "WHOIS":
                    whois_result = _run_provider(provider_reg, ioc, config)
                    if whois_result:
                        log.info("[WHOIS] Lookup executed")
                        provider_results.append(whois_result)
                        if whois_result.success:
                            log.info("[WHOIS] Lookup successful")
                        else:
                            log.info(f"[WHOIS] Failed: {whois_result.error.value if whois_result.error else 'unknown'}")
                    break
        
        # Step 3: Run remaining reputation providers for domains
        for provider_reg in PROVIDERS:
            if provider_reg.name not in ("RDAP", "WHOIS"):
                result = _run_provider(provider_reg, ioc, config)
                if result:
                    provider_results.append(result)

    # Standard flow for non-domain IOCs: run all supporting providers
    else:
        for provider_reg in PROVIDERS:
            result = _run_provider(provider_reg, ioc, config)
            if result:
                provider_results.append(result)

    # Aggregate all successful results into a single ThreatIntelResult
    aggregated = _aggregate_result(ioc, provider_results)

    return EnrichmentResult(
        ioc=ioc,
        result=aggregated,
        provider_results=provider_results,
    )