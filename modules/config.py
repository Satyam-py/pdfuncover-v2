# modules/config.py
"""
Configuration for the Threat Intelligence layer (modules/threat_intel.py,
modules/providers.py, modules/reputation.py).

Holds, per provider:
    - whether it is enabled
    - its API key (if any)
    - request timeout
    - retry count

This module intentionally knows nothing about HTTP or any specific
provider's API shape — it is pure configuration plumbing. Providers
(modules/providers.py) read a ProviderConfig and decide for themselves
what to do with it.

API key resolution order (first match wins), per provider:
    1. Environment variable, e.g. VT_API_KEY, URLHAUS_API_KEY, ...
    2. Local JSON config file (.threat_intel_config.json)
    3. None — the provider is then expected to report
       status="skipped", reason="API key not configured" rather than
       raising, exactly as required by callers of this module.

This module never raises on missing configuration. A missing/invalid
config file, a missing API key, or a malformed value all resolve to
safe defaults instead of an exception.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


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
# CONSTANTS
# ==========================================

CONFIG_FILE = ".threat_intel_config.json"

DEFAULT_TIMEOUT = 15          # seconds
DEFAULT_RETRIES = 2
DEFAULT_ENABLED = True

# Canonical provider names. modules/providers.py defines one class per
# entry here; modules/threat_intel.py wires them together.
PROVIDER_NAMES = (
    "virustotal",
    "urlhaus",
    "threatfox",
    "malwarebazaar",
    "otx",
    "abuseipdb",
    "google_safe_browsing",
    "urlscan",
)

# Env var used to look up each provider's API key, if not found in the
# JSON config file.
_ENV_KEY_NAMES: Dict[str, str] = {
    "virustotal":           "VT_API_KEY",
    "urlhaus":               "URLHAUS_API_KEY",
    "threatfox":             "THREATFOX_API_KEY",
    "malwarebazaar":         "MALWAREBAZAAR_API_KEY",
    "otx":                   "OTX_API_KEY",
    "abuseipdb":             "ABUSEIPDB_API_KEY",
    "google_safe_browsing":  "GOOGLE_SAFE_BROWSING_API_KEY",
    "urlscan":               "URLSCAN_API_KEY",
}


# ==========================================
# DATA MODEL
# ==========================================

@dataclass
class ProviderConfig:
    """Resolved configuration for a single threat-intel provider."""

    name: str
    enabled: bool = DEFAULT_ENABLED
    api_key: Optional[str] = None
    timeout: int = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)


# ==========================================
# LOCAL CONFIG FILE
# ==========================================

def _load_config_file() -> Dict[str, Any]:
    """
    Load the local JSON config file. Returns {} if missing/corrupt —
    this module never raises on bad configuration.

    Expected shape:
        {
            "providers": {
                "virustotal": {
                    "enabled": true,
                    "api_key": "...",
                    "timeout": 15,
                    "retries": 2
                },
                ...
            }
        }
    """

    if not os.path.exists(CONFIG_FILE):
        return {}

    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as e:
        log.error(f"Could not read {CONFIG_FILE}: {e}")
        return {}


def save_provider_api_key(provider: str, api_key: str) -> bool:
    """
    Persist an API key for a provider into the local JSON config file.
    Returns True on success, False on failure (never raises).
    """

    if provider not in PROVIDER_NAMES:
        log.error(f"Unknown provider name: {provider}")
        return False

    data = _load_config_file()
    providers = data.setdefault("providers", {})
    entry = providers.setdefault(provider, {})
    entry["api_key"] = api_key

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=4)
        return True
    except OSError as e:
        log.error(f"Could not write {CONFIG_FILE}: {e}")
        return False


# ==========================================
# RESOLUTION
# ==========================================

def _resolve_api_key(provider: str, file_entry: Dict[str, Any]) -> Optional[str]:
    """Env var takes precedence over the JSON config file."""

    env_var = _ENV_KEY_NAMES.get(provider)

    if env_var:
        env_val = os.environ.get(env_var)
        if env_val:
            return env_val

    file_val = file_entry.get("api_key")
    return file_val if isinstance(file_val, str) and file_val else None


def get_provider_config(provider: str) -> ProviderConfig:
    """
    Resolve full configuration for a single provider. Always returns a
    ProviderConfig — never raises, even for an unrecognized provider
    name (returned disabled with no key).
    """

    if provider not in PROVIDER_NAMES:
        log.error(f"Unknown provider requested: {provider}")
        return ProviderConfig(name=provider, enabled=False, api_key=None)

    file_data = _load_config_file()
    file_entry = file_data.get("providers", {}).get(provider, {})

    if not isinstance(file_entry, dict):
        file_entry = {}

    enabled = bool(file_entry.get("enabled", DEFAULT_ENABLED))

    try:
        timeout = int(file_entry.get("timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT

    try:
        retries = int(file_entry.get("retries", DEFAULT_RETRIES))
    except (TypeError, ValueError):
        retries = DEFAULT_RETRIES

    api_key = _resolve_api_key(provider, file_entry)

    return ProviderConfig(
        name=provider,
        enabled=enabled,
        api_key=api_key,
        timeout=timeout,
        retries=retries,
    )


def get_all_provider_configs() -> Dict[str, ProviderConfig]:
    """Resolve configuration for every known provider at once."""

    return {name: get_provider_config(name) for name in PROVIDER_NAMES}


def is_provider_enabled(provider: str) -> bool:
    """True only if the provider is enabled AND has an API key configured."""

    cfg = get_provider_config(provider)
    return cfg.enabled and cfg.has_api_key


# ==========================================
# THREAT INTEL CONFIG (aggregate)
# ==========================================

@dataclass
class ThreatIntelConfig:
    """
    Aggregate configuration object handed to ThreatIntelManager
    (modules/threat_intel.py). Bundles per-provider configs plus any
    manager-level defaults.
    """

    providers: Dict[str, ProviderConfig] = field(default_factory=dict)
    default_timeout: int = DEFAULT_TIMEOUT
    default_retries: int = DEFAULT_RETRIES

    @classmethod
    def load(cls) -> "ThreatIntelConfig":
        """Build a ThreatIntelConfig from env vars + the local config file."""
        return cls(providers=get_all_provider_configs())

    def get(self, provider: str) -> ProviderConfig:
        return self.providers.get(provider) or get_provider_config(provider)