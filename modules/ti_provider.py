# modules/ti_provider.py
"""
Provider interface for the redesigned threat-intelligence layer
(Step 1).

Every provider — reputation or context — implements this same
four-method surface, so no caller ever needs to know which concrete
provider it's talking to. This is the enforcement point for "no
provider-specific APIs should leak outside": the return type is
Optional[ProviderResult], which only ever carries ReputationFinding /
DomainContext / IPContext / LookupError, never a raw provider payload
on its own.

No concrete providers are implemented here. This is the abstract base
that a future migration step (NOT part of Step 1) would have
VirusTotalProvider, OTXProvider, WhoisProvider, RdapProvider, etc.
subclass, replacing their current homes in modules/providers.py one at
a time. Until that migration happens, modules/providers.py remains the
working implementation and is untouched.
"""

from abc import ABC
from enum import Enum
from typing import Optional

from modules.ti_models import Ioc, ProviderResult


class ProviderCategory(Enum):
    """
    The two provider categories called for in the redesign:
      - REPUTATION: returns a verdict (VirusTotal, OTX, URLScan,
        AbuseIPDB, ...).
      - CONTEXT: returns only facts, never a verdict (WHOIS, RDAP).
        Whether a fact is suspicious is decided by
        modules/correlation.py, not the provider itself.
    """

    REPUTATION = "reputation"
    CONTEXT = "context"


class Provider(ABC):
    """
    Common interface for every threat-intelligence provider.

    Subclasses implement only the lookup_* methods their service
    actually supports. The base class default for each is "not
    supported" (returns None) — mirroring the same "uniform surface,
    per-provider partial support" pattern the legacy BaseProvider in
    modules/providers.py already uses, but with a typed return value
    instead of a status="not_supported" dict.

    Contract for every lookup_* method:
        - Returns None if this provider does not support this IOC
          type at all (e.g. a hash-only provider's lookup_url).
        - Returns a ProviderResult wrapping a LookupError if the
          provider supports this IOC type but the lookup did not
          produce usable data (not configured, rate limited, no
          results, or a hard failure — see modules/ti_errors.py).
        - Returns a ProviderResult wrapping a ReputationFinding (for
          REPUTATION providers) or a DomainContext/IPContext (for
          CONTEXT providers) on success.
        - Never raises. A provider implementation that cannot
          guarantee this should catch its own exceptions and return a
          LookupError with reason=LOOKUP_FAILED instead.
    """

    name: str
    category: ProviderCategory

    def lookup_url(self, ioc: Ioc) -> Optional[ProviderResult]:
        return None

    def lookup_domain(self, ioc: Ioc) -> Optional[ProviderResult]:
        return None

    def lookup_ip(self, ioc: Ioc) -> Optional[ProviderResult]:
        return None

    def lookup_hash(self, ioc: Ioc) -> Optional[ProviderResult]:
        return None