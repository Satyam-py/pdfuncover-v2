# modules/providers.py
"""
One provider class per external threat-intelligence service.

Every provider implements the same four-method surface:

    lookup_url(url)
    lookup_domain(domain)
    lookup_ip(ip)
    lookup_hash(file_hash)

...but only overrides the ones it actually supports. The BaseProvider
default for any unsupported lookup type returns status="not_supported"
rather than raising, so modules/threat_intel.py can call every method
on every provider uniformly and simply skip anything that isn't
applicable.

Every provider call is defensive:
    - Missing/disabled API key   -> status="skipped",
                                     reason="API key not configured"
    - Network/HTTP/parse failure -> status="error", reason=<message>
    - Success                    -> status="success", raw=<provider JSON>

No provider here raises an exception out to its caller. This module
performs no correlation, scoring, or normalization across providers —
that is modules/reputation.py's job. It also is not wired into
analyzer.py, iocs.py, or report generation; it is a standalone,
reusable lookup layer.
"""

import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from modules.config import ProviderConfig, get_provider_config


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
# RESULT HELPERS
# ==========================================

def make_result(
    provider: str,
    ioc: str,
    ioc_type: str,
    status: str,
    reason: Optional[str] = None,
    malicious: Optional[bool] = None,
    score: Optional[float] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Standardized single-provider lookup result. This is the *provider*
    layer's output — modules/reputation.py further normalizes and
    correlates a list of these into one unified response.
    """

    return {
        "provider": provider,
        "ioc": ioc,
        "ioc_type": ioc_type,
        "status": status,
        "reason": reason,
        "malicious": malicious,
        "score": score,
        "raw": raw,
    }


# ==========================================
# BASE PROVIDER
# ==========================================

class BaseProvider:
    """
    Common request/retry/timeout plumbing and the "not supported"
    default for all four lookup methods. Subclasses override only the
    lookup_* methods their service actually offers.
    """

    name = "base"

    def __init__(self, config: Optional[ProviderConfig] = None):
        self.config = config or get_provider_config(self.name)

    # ---- lookup surface (default: unsupported) ----

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return self._not_supported(url, "url")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._not_supported(domain, "domain")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return self._not_supported(ip, "ip")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self._not_supported(file_hash, "hash")

    # ---- shared helpers ----

    def _not_supported(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        return make_result(
            self.name, ioc, ioc_type,
            status="not_supported",
            reason=f"{self.name} does not support {ioc_type} lookups",
        )

    def _skip(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        return make_result(
            self.name, ioc, ioc_type,
            status="skipped",
            reason="API key not configured",
        )

    def _ready(self) -> bool:
        """True if this provider is enabled and has a usable API key."""
        return bool(self.config and self.config.enabled and self.config.has_api_key)

    def _request(
        self,
        method: str,
        url: str,
        ioc: str,
        ioc_type: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Perform an HTTP request with the provider's configured timeout
        and retry count. Returns a raw requests.Response on success,
        or a standardized error result dict on failure. Callers should
        check `isinstance(result, requests.Response)` — see subclasses
        below for the pattern.
        """

        timeout = self.config.timeout
        attempts = max(1, self.config.retries + 1)
        last_error: Optional[str] = None

        for attempt in range(attempts):

            try:
                response = requests.request(
                    method, url, timeout=timeout, **kwargs
                )
                return response

            except requests.exceptions.Timeout:
                last_error = f"Request timed out after {timeout}s"

            except requests.exceptions.RequestException as e:
                last_error = str(e)

            if attempt < attempts - 1:
                time.sleep(min(2 ** attempt, 5))

        log.error(f"{self.name}: request to {url} failed: {last_error}")

        return make_result(
            self.name, ioc, ioc_type,
            status="error",
            reason=last_error or "Unknown request error",
        )


# ==========================================
# VIRUSTOTAL
# ==========================================

class VirusTotalProvider(BaseProvider):
    """VirusTotal v3 API — supports URL, domain, IP, and file-hash lookups."""

    name = "virustotal"
    BASE_URL = "https://www.virustotal.com/api/v3"

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.config.api_key}

    def _stats_result(
        self, ioc: str, ioc_type: str, endpoint: str
    ) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(ioc, ioc_type)

        result = self._request(
            "GET", f"{self.BASE_URL}/{endpoint}",
            ioc=ioc, ioc_type=ioc_type, headers=self._headers(),
        )

        if isinstance(result, dict):
            return result

        try:
            if result.status_code == 404:
                return make_result(
                    self.name, ioc, ioc_type, status="success",
                    malicious=False,
                    raw={"found": False},
                )

            result.raise_for_status()
            data = result.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)

            return make_result(
                self.name, ioc, ioc_type, status="success",
                malicious=malicious_count > 0,
                score=float(malicious_count),
                raw=data,
            )

        except (KeyError, ValueError) as e:
            log.error(f"virustotal: malformed response for {ioc}: {e}")
            return make_result(
                self.name, ioc, ioc_type, status="error",
                reason=f"Malformed VirusTotal response: {e}",
            )
        except requests.exceptions.HTTPError as e:
            return make_result(
                self.name, ioc, ioc_type, status="error", reason=str(e)
            )

    def lookup_url(self, url: str) -> Dict[str, Any]:
        # VT identifies URLs by the base64 (no padding) of the URL string.
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._stats_result(url, "url", f"urls/{url_id}")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._stats_result(domain, "domain", f"domains/{domain}")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return self._stats_result(ip, "ip", f"ip_addresses/{ip}")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self._stats_result(file_hash, "hash", f"files/{file_hash}")


# ==========================================
# URLHAUS
# ==========================================

class URLHausProvider(BaseProvider):
    """abuse.ch URLhaus — URL lookups, keyed by API key in the header."""

    name = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def lookup_url(self, url: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(url, "url")

        result = self._request(
            "POST", f"{self.BASE_URL}/url/",
            ioc=url, ioc_type="url",
            headers={"Auth-Key": self.config.api_key},
            data={"url": url},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            found = data.get("query_status") == "ok"

            return make_result(
                self.name, url, "url", status="success",
                malicious=found,
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, url, "url", status="error", reason=str(e)
            )

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(file_hash, "hash")

        key = "md5_hash" if len(file_hash) == 32 else "sha256_hash"

        result = self._request(
            "POST", f"{self.BASE_URL}/payload/",
            ioc=file_hash, ioc_type="hash",
            headers={"Auth-Key": self.config.api_key},
            data={key: file_hash},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            found = data.get("query_status") == "ok"

            return make_result(
                self.name, file_hash, "hash", status="success",
                malicious=found,
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, file_hash, "hash", status="error", reason=str(e)
            )


# ==========================================
# THREATFOX
# ==========================================

class ThreatFoxProvider(BaseProvider):
    """abuse.ch ThreatFox — IOC search covering URLs, domains, and IPs."""

    name = "threatfox"
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def _search(self, ioc: str, ioc_type: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(ioc, ioc_type)

        result = self._request(
            "POST", self.BASE_URL,
            ioc=ioc, ioc_type=ioc_type,
            headers={"Auth-Key": self.config.api_key},
            json={"query": "search_ioc", "search_term": ioc},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            found = data.get("query_status") == "ok" and bool(data.get("data"))

            return make_result(
                self.name, ioc, ioc_type, status="success",
                malicious=found,
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, ioc, ioc_type, status="error", reason=str(e)
            )

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return self._search(url, "url")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._search(domain, "domain")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return self._search(ip, "ip")


# ==========================================
# MALWAREBAZAAR
# ==========================================

class MalwareBazaarProvider(BaseProvider):
    """abuse.ch MalwareBazaar — file-hash lookups only."""

    name = "malwarebazaar"
    BASE_URL = "https://mb-api.abuse.ch/api/v1/"

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(file_hash, "hash")

        result = self._request(
            "POST", self.BASE_URL,
            ioc=file_hash, ioc_type="hash",
            headers={"Auth-Key": self.config.api_key},
            data={"query": "get_info", "hash": file_hash},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            found = data.get("query_status") == "ok"

            return make_result(
                self.name, file_hash, "hash", status="success",
                malicious=found,
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, file_hash, "hash", status="error", reason=str(e)
            )


# ==========================================
# OTX (AlienVault Open Threat Exchange)
# ==========================================

class OTXProvider(BaseProvider):
    """AlienVault OTX — domain, IP, URL, and hash reputation via pulses."""

    name = "otx"
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def _headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": self.config.api_key}

    def _general(self, ioc: str, ioc_type: str, section: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(ioc, ioc_type)

        result = self._request(
            "GET", f"{self.BASE_URL}/{section}/{ioc}/general",
            ioc=ioc, ioc_type=ioc_type, headers=self._headers(),
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            pulse_count = (
                data.get("pulse_info", {}).get("count", 0)
                if isinstance(data.get("pulse_info"), dict) else 0
            )

            return make_result(
                self.name, ioc, ioc_type, status="success",
                malicious=pulse_count > 0,
                score=float(pulse_count),
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, ioc, ioc_type, status="error", reason=str(e)
            )

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._general(domain, "domain", "domain")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return self._general(ip, "ip", "IPv4")

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return self._general(url, "url", "url")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self._general(file_hash, "hash", "file")


# ==========================================
# ABUSEIPDB
# ==========================================

class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB — IP reputation / abuse-confidence scoring only."""

    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def lookup_ip(self, ip: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(ip, "ip")

        result = self._request(
            "GET", self.BASE_URL,
            ioc=ip, ioc_type="ip",
            headers={"Key": self.config.api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)

            return make_result(
                self.name, ip, "ip", status="success",
                malicious=score >= 50,
                score=float(score),
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, ip, "ip", status="error", reason=str(e)
            )


# ==========================================
# GOOGLE SAFE BROWSING
# ==========================================

class GoogleSafeBrowsingProvider(BaseProvider):
    """Google Safe Browsing v4 — URL threat-match lookups only."""

    name = "google_safe_browsing"
    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def lookup_url(self, url: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(url, "url")

        payload = {
            "client": {"clientId": "pdfuncover", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        result = self._request(
            "POST", self.BASE_URL,
            ioc=url, ioc_type="url",
            params={"key": self.config.api_key},
            json=payload,
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            matches = data.get("matches", [])

            return make_result(
                self.name, url, "url", status="success",
                malicious=bool(matches),
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, url, "url", status="error", reason=str(e)
            )


# ==========================================
# URLSCAN
# ==========================================

class UrlscanProvider(BaseProvider):
    """urlscan.io — URL/domain search API."""

    name = "urlscan"
    BASE_URL = "https://urlscan.io/api/v1/search/"

    def _search(self, ioc: str, ioc_type: str, query: str) -> Dict[str, Any]:

        if not self._ready():
            return self._skip(ioc, ioc_type)

        result = self._request(
            "GET", self.BASE_URL,
            ioc=ioc, ioc_type=ioc_type,
            headers={"API-Key": self.config.api_key},
            params={"q": query},
        )

        if isinstance(result, dict):
            return result

        try:
            result.raise_for_status()
            data = result.json()
            total = data.get("total", 0)

            malicious = any(
                entry.get("page", {}).get("status", "") == "malicious"
                or entry.get("verdicts", {}).get("overall", {}).get("malicious")
                for entry in data.get("results", [])
                if isinstance(entry, dict)
            )

            return make_result(
                self.name, ioc, ioc_type, status="success",
                malicious=malicious if total else False,
                score=float(total),
                raw=data,
            )
        except (ValueError, requests.exceptions.HTTPError) as e:
            return make_result(
                self.name, ioc, ioc_type, status="error", reason=str(e)
            )

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return self._search(url, "url", f'page.url:"{url}"')

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._search(domain, "domain", f'domain:"{domain}"')


# ==========================================
# REGISTRY
# ==========================================

# Every provider class this module defines, keyed by its canonical
# name (matches modules.config.PROVIDER_NAMES). modules/threat_intel.py
# uses this to instantiate the full provider set without hardcoding
# imports for each class individually.
PROVIDER_CLASSES = {
    VirusTotalProvider.name:          VirusTotalProvider,
    URLHausProvider.name:              URLHausProvider,
    ThreatFoxProvider.name:            ThreatFoxProvider,
    MalwareBazaarProvider.name:        MalwareBazaarProvider,
    OTXProvider.name:                  OTXProvider,
    AbuseIPDBProvider.name:            AbuseIPDBProvider,
    GoogleSafeBrowsingProvider.name:   GoogleSafeBrowsingProvider,
    UrlscanProvider.name:              UrlscanProvider,
}