# modules/threat_intel/providers/otx.py
"""
AlienVault OTX provider, following the same conventions as the
VirusTotal provider (modules/threat_intel/providers/virustotal.py).

Exposes lookup_url() / lookup_domain() / lookup_ip() / lookup_hash(),
each returning a ProviderResult. Raw OTX JSON never leaves this
module — every field is normalized into ThreatIntelResult /
ReputationFinding before being returned.

OTX has no AV-style detection stats. Its signal is pulses — threat
intelligence reports that reference the indicator. Since the model
layer is not being redesigned, pulse data is normalized onto the
existing ReputationFinding fields:
    - malicious / total  -> pulse count (closest OTX equivalent to a
                            detection ratio; there is no
                            suspicious/harmless/undetected split)
    - reputation          -> OTX's own numeric reputation score, when
                             the indicator type provides one (IPs)
    - threat_names        -> pulse names ("Pulse: <name>")
    - categories          -> everything else asked for per IOC type:
                             references, related indicator type
                             counts, related malware families, and
                             honeypot observations, each with a
                             readable label prefix
A pulse count of zero still produces a successful ProviderResult with
an empty ReputationFinding — never an error.
"""

import logging
import os
from urllib.parse import quote

import requests

from modules.threat_intel.models import (
    Ioc,
    IocType,
    ProviderResult,
    ThreatIntelResult,
    ReputationFinding,
    LookupError,
)

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

PROVIDER_NAME = "AlienVault OTX"

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
_TIMEOUT = 20

# Pulse tags that indicate the pulse is honeypot-sourced telemetry
# rather than a curated threat report — used to surface "Honeypot
# observations" for IP indicators.
_HONEYPOT_TAGS = {
    "honeypot", "tpot", "dionaea", "cowrie", "honeytrap",
    "suricata", "mailoney", "tanner", "sentrypeer", "fatt", "p0f",
}


# ==========================================
# HTTP HELPER
# ==========================================

def _headers(api_key):
    return {"X-OTX-API-KEY": api_key} if api_key else {}


def _request(url, api_key):
    """
    Perform a single OTX API GET request.
    Returns (json_dict, LookupError) — exactly one of the two is None.
    """

    try:
        r = requests.get(url, headers=_headers(api_key), timeout=_TIMEOUT)

    except requests.exceptions.Timeout:
        return None, LookupError.NETWORK_ERROR

    except requests.exceptions.RequestException as e:
        log.error(f"OTX request failed: {e}")
        return None, LookupError.NETWORK_ERROR

    if r.status_code == 404:
        return None, LookupError.NOT_FOUND

    if r.status_code in (401, 403):
        return None, LookupError.AUTH_ERROR

    if r.status_code == 429:
        return None, LookupError.RATE_LIMITED

    if r.status_code >= 400:
        return None, LookupError.UNKNOWN

    try:
        return r.json(), None

    except ValueError as e:
        log.error(f"OTX response JSON parse failed: {e}")
        return None, LookupError.PARSE_ERROR


# ==========================================
# SHARED NORMALIZATION HELPERS
# ==========================================

def _extract_pulses(data):
    """
    Pull the pulse list and summary fields out of an OTX 'general'
    response. Returns (count, names, references, pulses) — `pulses`
    is the raw per-pulse list, kept only for the per-type helpers
    below to derive further fields from (malware families, tags,
    indicator_type_counts); it never leaves this module.
    """

    pulse_info = data.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []

    count = pulse_info.get("count", 0)
    names = [p.get("name") for p in pulses if p.get("name")]
    references = pulse_info.get("references", []) or []

    return count, names, references, pulses


def _related_malware_families(pulses):
    families = set()
    for p in pulses:
        families.update(p.get("malware_families") or [])
    return sorted(families)


def _related_indicator_counts(pulses):
    """Aggregate each pulse's indicator_type_counts into one summary list."""

    combined = {}

    for p in pulses:
        for ind_type, ind_count in (p.get("indicator_type_counts") or {}).items():
            combined[ind_type] = combined.get(ind_type, 0) + ind_count

    return [f"{ind_type}: {ind_count}" for ind_type, ind_count in sorted(combined.items())]


def _honeypot_observations(pulses):
    """Names of pulses whose tags indicate honeypot-sourced telemetry."""

    observations = []

    for p in pulses:
        tags = {t.lower() for t in (p.get("tags") or [])}
        if tags & _HONEYPOT_TAGS:
            name = p.get("name")
            if name:
                observations.append(name)

    return observations


def _build_reputation(count, names, categories, reputation_score, permalink):
    return ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=count,
        suspicious=0,
        harmless=0,
        undetected=0,
        total=count,
        reputation=reputation_score,
        categories=categories,
        threat_names=[f"Pulse: {n}" for n in names],
        permalink=permalink,
    )


# ==========================================
# URL
# ==========================================

def lookup_url(url, api_key):
    """Look up a URL's OTX pulse activity."""

    ioc = Ioc(value=url, type=IocType.URL)
    encoded = quote(url, safe="")

    data, err = _request(f"{_BASE_URL}/url/{encoded}/general", api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    count, names, references, _pulses = _extract_pulses(data)

    categories = [f"Reference: {ref}" for ref in references]

    reputation = _build_reputation(
        count, names, categories,
        reputation_score=data.get("reputation"),
        permalink=f"https://otx.alienvault.com/indicator/url/{encoded}",
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# DOMAIN
# ==========================================

def lookup_domain(domain, api_key):
    """Look up a domain's OTX pulse activity."""

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    data, err = _request(f"{_BASE_URL}/domain/{domain}/general", api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    count, names, references, pulses = _extract_pulses(data)

    categories = [f"Reference: {ref}" for ref in references]
    categories += [f"Related indicator: {entry}" for entry in _related_indicator_counts(pulses)]

    reputation = _build_reputation(
        count, names, categories,
        reputation_score=data.get("reputation"),
        permalink=f"https://otx.alienvault.com/indicator/domain/{domain}",
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# IP
# ==========================================

def lookup_ip(ip, api_key):
    """Look up an IP's OTX pulse activity."""

    ioc = Ioc(value=ip, type=IocType.IP)

    data, err = _request(f"{_BASE_URL}/IPv4/{ip}/general", api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    count, names, references, pulses = _extract_pulses(data)

    categories = [f"Reference: {ref}" for ref in references]
    categories += [f"Related malware: {fam}" for fam in _related_malware_families(pulses)]
    categories += [f"Honeypot observation: {name}" for name in _honeypot_observations(pulses)]

    reputation = _build_reputation(
        count, names, categories,
        reputation_score=data.get("reputation"),
        permalink=f"https://otx.alienvault.com/indicator/ip/{ip}",
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# HASH
# ==========================================

def lookup_hash(file_hash, api_key):
    """Look up a file hash's OTX pulse activity."""

    ioc = Ioc(value=file_hash, type=IocType.HASH)

    data, err = _request(f"{_BASE_URL}/file/{file_hash}/general", api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    count, names, _references, _pulses = _extract_pulses(data)

    reputation = _build_reputation(
        count, names, categories=[],
        reputation_score=data.get("reputation"),
        permalink=f"https://otx.alienvault.com/indicator/file/{file_hash}",
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)