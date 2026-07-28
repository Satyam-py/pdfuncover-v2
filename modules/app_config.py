# modules/app_config.py
"""
Single configuration source for PDFUncover.

Consolidates what used to be two separate config files/loaders:
    - main.py's ".pdfuncover_config.json" (VirusTotal key used for the
      direct hash lookup in main.py)
    - modules/threat_intel_pipeline.py's ".threat_intel_config.json"
      (VirusTotal/OTX/AbuseIPDB keys used for IOC enrichment)

Both now read/write the same file, in one flat shape:

    {
        "virustotal_api_key": "...",
        "otx_api_key": "...",
        "abuseipdb_api_key": "...",
        "urlscan_api_key": "..."
    }

Resolution order per key (same precedence both prior loaders already
used independently — just applied consistently now):
    1. Environment variable (VT_API_KEY / OTX_API_KEY / ABUSEIPDB_API_KEY / URLSCAN_API_KEY)
    2. This config file
    3. Not configured -> caller treats the provider as unavailable;
       nothing here ever raises.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

CONFIG_FILE = ".pdfuncover_config.json"

# provider config key (matches ProviderRegistration.config_key values
# in modules/threat_intel/engine.py) -> environment variable name
_ENV_KEY_NAMES: Dict[str, str] = {
    "virustotal_api_key": "VT_API_KEY",
    "otx_api_key": "OTX_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "urlscan_api_key": "URLSCAN_API_KEY",
}


def load_config() -> Dict[str, Any]:
    """Load the local JSON config file. Returns {} if missing/corrupt —
    never raises."""

    if not os.path.exists(CONFIG_FILE):
        return {}

    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as e:
        log.error(f"Could not read {CONFIG_FILE}: {e}")
        return {}


def save_api_key(api_key: str, config_key: str = "virustotal_api_key") -> None:
    """
    Persist an API key into the single config file.

    Defaults to "virustotal_api_key" so main.py's existing
    `--add-api-key` CLI flag keeps behaving exactly as before — that
    flag has only ever set the VirusTotal key.
    """

    config = load_config()
    config[config_key] = api_key

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def get_api_key(config_key: str) -> Optional[str]:
    """
    Resolve a single provider's API key: environment variable first,
    then the config file. Shared by main.py (VirusTotal hash lookup)
    and modules/threat_intel_pipeline.py (IOC enrichment).
    """

    env_var = _ENV_KEY_NAMES.get(config_key)

    if env_var:
        env_val = os.environ.get(env_var)
        if env_val:
            return env_val

    file_val = load_config().get(config_key)
    return file_val if isinstance(file_val, str) and file_val else None


def get_provider_config() -> Dict[str, str]:
    """
    Resolve every known provider's API key at once — the
    {config_key: api_key} shape modules/threat_intel_pipeline.py's
    enrich_extracted_iocs() expects as its `config` argument. Omits
    any key that isn't configured anywhere.
    """

    resolved: Dict[str, str] = {}

    for config_key in _ENV_KEY_NAMES:
        value = get_api_key(config_key)
        if value:
            resolved[config_key] = value

    return resolved