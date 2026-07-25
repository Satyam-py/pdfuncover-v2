# modules/threat_intel.py
"""
ThreatIntelManager — the single entry point for all IOC lookups.

Wires together:
    modules/config.py       (which providers are enabled, API keys, timeouts)
    modules/providers.py    (one class per external service)
    modules/reputation.py   (normalization, correlation, scoring)

into four simple methods:

    lookup_url(url)
    lookup_domain(domain)
    lookup_ip(ip)
    lookup_hash(file_hash)

Each returns a single unified reputation response (see
modules.reputation.build_unified_response) built from every enabled
provider that supports that IOC type. Providers that error, are
disabled, or lack an API key never raise — they're reflected in the
response's "providers" detail and correlation counts instead.

This module is standalone and reusable. It is NOT wired into
analyzer.py, iocs.py, or report generation, and does not alter any
existing detection/scoring behavior — those integrations are a
deliberate follow-up step, not part of this module.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from modules.config import ThreatIntelConfig, PROVIDER_NAMES
from modules.providers import PROVIDER_CLASSES, BaseProvider, make_result
from modules.reputation import build_unified_response


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
# MANAGER
# ==========================================

class ThreatIntelManager:
    """
    Central coordinator for threat-intelligence IOC lookups.

    Usage:
        manager = ThreatIntelManager()
        result = manager.lookup_url("http://example.com/bad")
        result = manager.lookup_ip("1.2.3.4")
        result = manager.lookup_hash(sha256)

    A specific provider subset can be supplied for testing / partial
    deployments:
        manager = ThreatIntelManager(provider_names=["virustotal", "otx"])
    """

    def __init__(
        self,
        config: Optional[ThreatIntelConfig] = None,
        provider_names: Optional[List[str]] = None,
    ):
        self.config = config or ThreatIntelConfig.load()
        self._provider_names = list(provider_names or PROVIDER_NAMES)
        self._providers: Dict[str, BaseProvider] = self._build_providers()

    # ---- setup ----

    def _build_providers(self) -> Dict[str, BaseProvider]:
        """
        Instantiate one provider object per requested provider name.
        A provider class failing to construct (should not normally
        happen — construction does no I/O) is logged and skipped
        rather than aborting the whole manager.
        """

        providers: Dict[str, BaseProvider] = {}

        for name in self._provider_names:

            provider_cls = PROVIDER_CLASSES.get(name)

            if provider_cls is None:
                log.error(f"No provider class registered for '{name}'")
                continue

            try:
                providers[name] = provider_cls(self.config.get(name))
            except Exception as e:
                log.error(f"Failed to initialize provider '{name}': {e}")

        return providers

    # ---- internal lookup runner ----

    def _run_lookup(
        self, ioc: str, ioc_type: str, method_name: str
    ) -> Dict[str, Any]:
        """
        Call `method_name` (one of lookup_url/lookup_domain/lookup_ip/
        lookup_hash) on every configured provider, collect the raw
        per-provider results, and hand them to reputation.py for
        normalization/correlation/scoring.

        A provider raising an unexpected exception is caught here and
        converted into a standardized "error" result so one bad
        provider can never break the aggregate lookup.
        """

        raw_results: List[Dict[str, Any]] = []

        for name, provider in self._providers.items():

            method = getattr(provider, method_name, None)

            if method is None:
                continue

            try:
                result = method(ioc)
            except Exception as e:
                log.error(f"{name}.{method_name}({ioc!r}) raised: {e}")
                result = make_result(
                    name, ioc, ioc_type,
                    status="error",
                    reason=f"Unhandled provider exception: {e}",
                )

            raw_results.append(result)

        return build_unified_response(ioc, ioc_type, raw_results)

    # ---- public API ----

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Unified reputation lookup for a URL across all supporting providers."""
        return self._run_lookup(url, "url", "lookup_url")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Unified reputation lookup for a domain across all supporting providers."""
        return self._run_lookup(domain, "domain", "lookup_domain")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Unified reputation lookup for an IP address across all supporting providers."""
        return self._run_lookup(ip, "ip", "lookup_ip")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Unified reputation lookup for a file hash across all supporting providers."""
        return self._run_lookup(file_hash, "hash", "lookup_hash")

    # ---- introspection ----

    def enabled_providers(self) -> List[str]:
        """
        Names of providers that are both instantiated and actually
        ready (enabled + API key configured) — i.e. will contribute a
        real result rather than an automatic "skipped".
        """

        return [
            name for name, provider in self._providers.items()
            if provider._ready()
        ]

    def configured_providers(self) -> List[str]:
        """Names of every provider this manager was built with, regardless of readiness."""
        return list(self._providers.keys())