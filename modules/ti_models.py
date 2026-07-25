# modules/ti_models.py
"""
Core data model for the redesigned threat-intelligence layer (Step 1).

Separates the four things that were previously tangled together in
modules/providers.py + modules/reputation.py's dict-shaped results:

    Ioc -> Provider -> ProviderResult -> ThreatIntelResult -> Report

The report layer (and everything downstream of ThreatIntelResult)
should never need to know VirusTotal from OTX from RDAP — it only
ever sees these types.

This module performs no I/O, no scoring, and no correlation. It is a
pure data model: dataclasses in, dataclasses out. That is deliberate —
Step 1 is foundation only; scoring/correlation logic stays in
modules/reputation.py and modules/correlation.py until a later
migration step.

Reputation vs. context (per the two provider categories):
    - ReputationFinding: a provider's verdict on whether an IOC is
      malicious (VirusTotal, OTX, URLScan, AbuseIPDB, ...).
    - DomainContext / IPContext: purely factual data about an IOC
      (WHOIS/RDAP registrar, ASN, creation date, ...). These NEVER
      carry a verdict — a context provider reporting "registered
      3 days ago" is a fact, not a judgment. Whether that fact is
      suspicious is a correlation-layer decision (modules/correlation.py),
      not something a context provider or this model computes.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from modules.ti_errors import LookupError


# ==========================================
# IOC
# ==========================================

class IocType(Enum):
    """The four IOC categories this layer supports lookups for."""

    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"


@dataclass(frozen=True)
class Ioc:
    """
    A single indicator of compromise to look up. Immutable and
    hashable (frozen) so it can be used as a dict key or dedup set
    member, mirroring the dedup behavior modules/parsers/iocs.py and
    modules/parsers/ioc_enrichment.py already rely on.
    """

    value: str
    type: IocType


# ==========================================
# VERDICT
# ==========================================

class Verdict(Enum):
    """
    A reputation provider's opinion on one IOC. Only ReputationFinding
    carries this — context providers (WHOIS/RDAP) never do, by design.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


# ==========================================
# REPUTATION PROVIDERS
# ==========================================

@dataclass(frozen=True)
class ReputationFinding:
    """
    One reputation provider's verdict on one IOC. This is the
    replacement for the ad-hoc {"malicious": bool, "score": float,
    "raw": {...}} shape make_result() produces in the legacy
    modules/providers.py.

    `score` is optional and provider-defined (0-100 where a provider
    supplies one) — Step 1 does not normalize scores across providers
    or compute an aggregate; that remains modules/reputation.py's job.
    `raw` holds the provider's original response for debugging/audit
    only. It is intentionally NOT meant to be read by report code —
    "no provider-specific APIs should leak outside" means callers
    consume `verdict`/`score`, not `raw`.
    """

    provider: str
    ioc: Ioc
    verdict: Verdict
    score: Optional[float] = None
    detail: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# ==========================================
# CONTEXT PROVIDERS
# ==========================================

@dataclass(frozen=True)
class DomainContext:
    """
    Purely factual WHOIS/RDAP-style data about a domain. No verdict
    field exists here on purpose — a context provider reports facts,
    it does not decide whether a fact is suspicious (e.g. "registered
    2 days ago" is for modules/correlation.py's
    _looks_newly_registered()-style logic to interpret, not this
    provider).
    """

    ioc: Ioc
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    updated_date: Optional[str] = None
    expires_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    registrant_country: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class IPContext:
    """
    Purely factual RDAP/WHOIS-style data about an IP address. Kept
    separate from DomainContext rather than one shared ContextRecord —
    an IP's meaningful facts (ASN, network/CIDR, allocation) don't
    overlap enough with a domain's (registrar, nameservers) to share a
    shape without one side being mostly null.
    """

    ioc: Ioc
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    network: Optional[str] = None
    country: Optional[str] = None
    allocation_date: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


# ==========================================
# PROVIDER RESULT
# ==========================================

# What a single provider call for a single IOC can produce, besides
# None (unsupported — see ti_provider.py). Exactly one of these per
# call: a reputation provider yields ReputationFinding or LookupError;
# a context provider yields DomainContext/IPContext or LookupError.
ProviderPayload = Union[ReputationFinding, DomainContext, IPContext, LookupError]


@dataclass(frozen=True)
class ProviderResult:
    """
    The result of one provider's lookup for one IOC — the "Provider ->
    Normalized Provider Result" step of the pipeline. `payload` is a
    closed union; the three is_* properties let callers dispatch
    without isinstance-checking the union everywhere.
    """

    provider: str
    ioc: Ioc
    payload: ProviderPayload

    @property
    def is_error(self) -> bool:
        return isinstance(self.payload, LookupError)

    @property
    def is_reputation(self) -> bool:
        return isinstance(self.payload, ReputationFinding)

    @property
    def is_context(self) -> bool:
        return isinstance(self.payload, (DomainContext, IPContext))


# ==========================================
# THREAT INTEL RESULT
# ==========================================

@dataclass
class ThreatIntelResult:
    """
    Everything gathered about a single IOC across every configured
    provider — the "ThreatIntelResult -> Report" handoff point. This
    is the replacement for the dict modules.reputation.build_unified_
    response() produces today.

    Deliberately holds only collected data, not a computed verdict or
    score — aggregating reputation_findings into one verdict is a
    scoring/correlation decision and stays in modules/reputation.py /
    modules/correlation.py until those are migrated. The two
    properties below (`has_malicious_reputation`, `has_errors`) are
    simple existence checks over already-collected data, not scoring
    logic, so they stay here.
    """

    ioc: Ioc
    reputation_findings: List[ReputationFinding] = field(default_factory=list)
    domain_context: Optional[DomainContext] = None
    ip_context: Optional[IPContext] = None
    errors: List[LookupError] = field(default_factory=list)

    @property
    def has_malicious_reputation(self) -> bool:
        """True if any provider flagged this IOC malicious. Not a score,
        not a confidence level — just "did anyone say yes"."""
        return any(f.verdict == Verdict.MALICIOUS for f in self.reputation_findings)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    def add_provider_result(self, result: ProviderResult) -> None:
        """
        Fold one ProviderResult into this aggregate. Pure bookkeeping —
        no judgment about what the result means.
        """

        if result.is_error:
            self.errors.append(result.payload)  # type: ignore[arg-type]
        elif isinstance(result.payload, ReputationFinding):
            self.reputation_findings.append(result.payload)
        elif isinstance(result.payload, DomainContext):
            self.domain_context = result.payload
        elif isinstance(result.payload, IPContext):
            self.ip_context = result.payload