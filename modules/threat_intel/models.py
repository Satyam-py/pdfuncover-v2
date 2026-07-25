# modules/threat_intel/models.py
"""
Core typed models for the Threat Intelligence layer.

These are provider-agnostic. Every provider (VirusTotal, OTX, URLScan,
AbuseIPDB, WHOIS, RDAP) normalizes its raw response into these shapes
before returning anything — no provider-specific dicts or raw JSON
should leak past the provider module boundary.
"""

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional, List, Dict, Any, Callable


class IocType(Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"


class LookupError(Enum):
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    AUTH_ERROR = "auth_error"
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


@dataclass
class Ioc:
    value: str
    type: IocType


@dataclass
class ReputationFinding:
    """Output of a Reputation Provider (VirusTotal, OTX, URLScan, AbuseIPDB)."""

    provider: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    reputation: Optional[int] = None
    categories: List[str] = field(default_factory=list)
    threat_names: List[str] = field(default_factory=list)
    permalink: Optional[str] = None

    @property
    def detection_ratio(self) -> str:
        return f"{self.malicious}/{self.total}"


@dataclass
class DomainContext:
    """Output of a Context Provider for domains (WHOIS/RDAP, or VT's domain metadata)."""

    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    dns_records: List[str] = field(default_factory=list)


@dataclass
class IPContext:
    """Output of a Context Provider for IPs (RDAP, or VT's IP metadata)."""

    asn: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None


@dataclass
class FileContext:
    """Hash-specific analyst context (sandbox verdicts, threat classification, etc)."""

    file_type: Optional[str] = None
    meaningful_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    threat_label: Optional[str] = None
    threat_category: Optional[str] = None
    sandbox_verdicts: List[str] = field(default_factory=list)
    sigma_summary: Optional[Dict[str, Any]] = None
    last_analysis_date: Optional[str] = None


@dataclass
class UrlContext:
    """URL-specific analyst context (redirects, final destination, HTTP status)."""

    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    http_status: Optional[int] = None


@dataclass
class ThreatIntelResult:
    """Normalized, per-IOC result body returned by a provider on success."""

    ioc: Ioc
    reputation: Optional[ReputationFinding] = None
    reputations: List[ReputationFinding] = field(default_factory=list)
    domain_context: Optional[DomainContext] = None
    ip_context: Optional[IPContext] = None
    file_context: Optional[FileContext] = None
    url_context: Optional[UrlContext] = None


@dataclass
class ProviderResult:
    """
    Universal return type for every provider lookup_*() call.
    success=False means `error` is set and `data` is None.
    """

    provider: str
    ioc: Ioc
    success: bool
    data: Optional[ThreatIntelResult] = None
    error: Optional[LookupError] = None
    error_message: Optional[str] = None


# ==========================================
# PROVIDER REGISTRATION (typed, engine-facing)
# ==========================================

@dataclass
class ProviderRegistration:
    """
    Describes one provider's presence in the Threat Intelligence Engine.

    Replaces the previous ad-hoc dict-based registry entry. Every field
    here is explicit and required (aside from config_key, which only
    applies when requires_api_key is True), so a malformed registration
    fails at construction time rather than via a missing dict key.
    """

    name: str
    supported_types: List[IocType]
    lookups: Dict[IocType, Callable[..., ProviderResult]]
    requires_api_key: bool
    config_key: Optional[str] = None

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in self.supported_types and ioc_type in self.lookups


# ==========================================
# ENGINE RESULT (typed, engine-facing)
# ==========================================

@dataclass
class EnrichmentResult:
    """
    Complete, typed output of Engine.enrich_ioc().

    Replaces the previous plain dict return shape. `result` is the
    field-by-field aggregated ThreatIntelResult across every provider
    that ran; `provider_results` preserves each individual provider's
    raw ProviderResult (including failures) for callers that need
    per-provider detail (e.g. showing which provider errored).
    """

    ioc: Ioc
    result: ThreatIntelResult
    provider_results: List[ProviderResult] = field(default_factory=list)


# ==========================================
# FIELD-BY-FIELD CONTEXT MERGING
# ==========================================
#
# Each merge_* helper takes the currently-accumulated context (possibly
# None) and a newly-arrived context from another provider, and returns
# a context where already-populated fields are preserved and only
# still-missing fields are filled in from the new source. List fields
# are unioned (order-preserving, de-duplicated) rather than treated as
# "missing vs present", since multiple providers can each contribute
# distinct list entries (e.g. different DNS records).

def _first_non_empty(*values):
    for v in values:
        if v:
            return v
    return None


def _union_lists(*lists):
    seen = []
    for lst in lists:
        for item in lst or []:
            if item not in seen:
                seen.append(item)
    return seen


def merge_domain_context(
    existing: Optional[DomainContext], new: Optional[DomainContext]
) -> Optional[DomainContext]:

    if existing is None:
        return new
    if new is None:
        return existing

    return DomainContext(
        registrar=_first_non_empty(existing.registrar, new.registrar),
        creation_date=_first_non_empty(existing.creation_date, new.creation_date),
        dns_records=_union_lists(existing.dns_records, new.dns_records),
    )


def merge_ip_context(
    existing: Optional[IPContext], new: Optional[IPContext]
) -> Optional[IPContext]:

    if existing is None:
        return new
    if new is None:
        return existing

    return IPContext(
        asn=_first_non_empty(existing.asn, new.asn),
        organization=_first_non_empty(existing.organization, new.organization),
        country=_first_non_empty(existing.country, new.country),
        network=_first_non_empty(existing.network, new.network),
    )


def merge_file_context(
    existing: Optional[FileContext], new: Optional[FileContext]
) -> Optional[FileContext]:

    if existing is None:
        return new
    if new is None:
        return existing

    return FileContext(
        file_type=_first_non_empty(existing.file_type, new.file_type),
        meaningful_name=_first_non_empty(existing.meaningful_name, new.meaningful_name),
        tags=_union_lists(existing.tags, new.tags),
        threat_label=_first_non_empty(existing.threat_label, new.threat_label),
        threat_category=_first_non_empty(existing.threat_category, new.threat_category),
        sandbox_verdicts=_union_lists(existing.sandbox_verdicts, new.sandbox_verdicts),
        sigma_summary=existing.sigma_summary or new.sigma_summary,
        last_analysis_date=_first_non_empty(
            existing.last_analysis_date, new.last_analysis_date
        ),
    )


def merge_url_context(
    existing: Optional[UrlContext], new: Optional[UrlContext]
) -> Optional[UrlContext]:

    if existing is None:
        return new
    if new is None:
        return existing

    return UrlContext(
        final_url=_first_non_empty(existing.final_url, new.final_url),
        redirect_chain=_union_lists(existing.redirect_chain, new.redirect_chain),
        http_status=existing.http_status if existing.http_status is not None else new.http_status,
    )