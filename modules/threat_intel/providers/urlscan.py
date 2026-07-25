# modules/threat_intel/providers/urlscan.py
"""
urlscan.io provider, following the same conventions as the
VirusTotal and OTX providers (modules/threat_intel/providers/
virustotal.py, modules/threat_intel/providers/otx.py).

Exposes lookup_url() / lookup_domain() / lookup_ip(), each returning a
ProviderResult. Raw urlscan.io JSON never leaves this module — every
field is normalized into ThreatIntelResult / ReputationFinding /
UrlContext / IPContext before being returned.

lookup_hash() does not exist — urlscan.io has no hash-lookup surface,
so hashes are simply left unsupported (no function, and HASH is
omitted from the provider's ProviderRegistration in engine.py), the
same way any provider only implements the lookup_* functions its
service actually offers.

This provider is search-only. It never submits a new scan (POST
/api/v1/scan/) — that would create a live, visible scan as a side
effect of a passive lookup, which is out of scope for an enrichment
provider. lookup_url() only queries for scans that already exist via
GET /api/v1/search/, then (when a matching scan is found) fetches the
full result via GET /api/v1/result/{uuid}/ for richer fields
(technologies, redirect chain, observed domains/IPs). If that second
call fails, the lookup still succeeds using only the fields already
present in the search hit — a missing detail fetch is not treated as
a lookup failure.

Field mapping notes (existing models are not redesigned — everything
below fits into fields that already exist):
    - reputation.malicious / .harmless / .total -> urlscan has no
      per-engine AV consensus; verdicts.overall.malicious is a single
      boolean per scan. malicious/harmless/total are populated as 1/0
      pairs per scan found, so ReputationFinding.detection_ratio still
      reads sensibly (e.g. "1/1" or "0/3" across multiple scans for a
      domain/IP lookup).
    - reputation.reputation -> verdicts.overall.score, when present.
    - reputation.threat_names -> verdicts.overall.categories.
    - reputation.categories -> everything else this task asks for
      that has no dedicated field: "Screenshot: <url>",
      "Page title: <title>", "Technology: <name>",
      "Domain observed: <domain>", "IP observed: <ip>",
      "Report: <url>" — same labeled-string convention OTX already
      uses for its "Reference:" / "Related indicator:" entries.
    - url_context.redirect_chain -> formatted from the result's
      `redirects` list ("from -> to (status)"), when available.
    - domain/ip lookups reuse the same search endpoint with a
      different query field and aggregate across every scan found,
      since urlscan has no single-record "give me everything about
      this domain" endpoint the way VirusTotal does.
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
    IPContext,
    UrlContext,
    LookupError,
)

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/threat_intel.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

PROVIDER_NAME = "URLScan"

_BASE_URL = "https://urlscan.io/api/v1"
_TIMEOUT = 20

# Cap on how many search hits are folded into a domain/IP aggregate —
# urlscan searches can return large result sets; this keeps the
# categories list readable rather than dumping every scan ever seen.
_MAX_AGGREGATED_HITS = 10


# ==========================================
# HTTP HELPER
# ==========================================

def _headers(api_key):
    return {"API-Key": api_key} if api_key else {}


def _request(url, api_key):
    """
    Perform a single urlscan.io API GET request.
    Returns (json_dict, LookupError) — exactly one of the two is None.
    """

    try:
        r = requests.get(url, headers=_headers(api_key), timeout=_TIMEOUT)

    except requests.exceptions.Timeout:
        return None, LookupError.NETWORK_ERROR

    except requests.exceptions.RequestException as e:
        log.error(f"urlscan.io request failed: {e}")
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
        log.error(f"urlscan.io response JSON parse failed: {e}")
        return None, LookupError.PARSE_ERROR


def _search(query, api_key):
    """GET /search/?q=<query> — find existing scans matching `query`."""
    url = f"{_BASE_URL}/search/?q={quote(query)}"
    return _request(url, api_key)


def _result(uuid, api_key):
    """GET /result/{uuid}/ — full detail for one specific scan."""
    url = f"{_BASE_URL}/result/{uuid}/"
    return _request(url, api_key)


# ==========================================
# SHARED NORMALIZATION HELPERS
# ==========================================

def _technologies(source):
    """App names detected by urlscan's Wappalyzer-derived processor, if present."""

    wappa = (
        source.get("meta", {})
        .get("processors", {})
        .get("wappa", {})
        .get("data", [])
        or []
    )
    return [entry.get("app") for entry in wappa if entry.get("app")]


def _redirect_chain(source):
    """Format the `redirects` list (present on full /result/ responses only)."""

    formatted = []

    for r in source.get("redirects", []) or []:
        from_url = r.get("from")
        to_url = r.get("to")
        status = r.get("status")
        if from_url and to_url:
            formatted.append(f"{from_url} -> {to_url} ({status})")

    return formatted


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _overall_verdict(source):
    """(malicious: bool, score, categories) from a scan's verdicts.overall block."""

    overall = (source.get("verdicts") or {}).get("overall", {}) or {}
    return bool(overall.get("malicious")), overall.get("score"), overall.get("categories") or []


def _permalink(source, uuid):
    return source.get("task", {}).get("reportURL") or (
        f"https://urlscan.io/result/{uuid}/" if uuid else None
    )


# ==========================================
# URL
# ==========================================

def lookup_url(url, api_key):
    """Look up a URL's most recent urlscan.io scan."""

    ioc = Ioc(value=url, type=IocType.URL)

    data, err = _search(f'page.url:"{url}"', api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    hits = data.get("results", []) or []

    if not hits:
        # No prior scan on record — a valid, successful "nothing found"
        # result, same as OTX's zero-pulse case. Not an error.
        result = ThreatIntelResult(ioc=ioc)
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)

    top = hits[0]
    uuid = top.get("task", {}).get("uuid")

    source = top

    if uuid:
        detail, detail_err = _result(uuid, api_key)
        if detail_err:
            log.error(f"urlscan.io detail fetch failed for {uuid}: {detail_err}")
        else:
            source = detail

    page = source.get("page", {}) or {}
    task = source.get("task", {}) or {}

    malicious, score, threat_categories = _overall_verdict(source)

    categories = []

    screenshot = task.get("screenshotURL")
    if screenshot:
        categories.append(f"Screenshot: {screenshot}")

    title = page.get("title")
    if title:
        categories.append(f"Page title: {title}")

    for tech in _technologies(source):
        categories.append(f"Technology: {tech}")

    for domain in source.get("lists", {}).get("domains", []) or [page.get("domain")]:
        if domain:
            categories.append(f"Domain observed: {domain}")

    for ip in source.get("lists", {}).get("ips", []) or [page.get("ip")]:
        if ip:
            categories.append(f"IP observed: {ip}")

    report_url = task.get("reportURL")
    if report_url:
        categories.append(f"Report: {report_url}")

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=1 if malicious else 0,
        suspicious=0,
        harmless=0 if malicious else 1,
        undetected=0,
        total=1,
        reputation=score,
        categories=categories,
        threat_names=threat_categories,
        permalink=_permalink(source, uuid),
    )

    url_context = UrlContext(
        final_url=page.get("url"),
        redirect_chain=_redirect_chain(source),
        http_status=_as_int(page.get("status")),
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, url_context=url_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# DOMAIN
# ==========================================

def lookup_domain(domain, api_key):
    """
    Look up a domain's urlscan.io scan history.

    Aggregates across every scan found (capped at
    _MAX_AGGREGATED_HITS) rather than resolving to one record — there
    is no single "everything about this domain" urlscan endpoint the
    way VirusTotal's /domains/ endpoint provides.
    """

    ioc = Ioc(value=domain, type=IocType.DOMAIN)

    data, err = _search(f'domain:"{domain}"', api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    hits = (data.get("results", []) or [])[:_MAX_AGGREGATED_HITS]

    if not hits:
        result = ThreatIntelResult(ioc=ioc)
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)

    malicious_count = 0
    categories = []
    seen_urls = set()
    seen_ips = set()

    for hit in hits:
        is_malicious, _score, _cats = _overall_verdict(hit)
        if is_malicious:
            malicious_count += 1

        page = hit.get("page", {}) or {}

        url = page.get("url")
        if url and url not in seen_urls:
            seen_urls.add(url)
            categories.append(f"URL observed: {url}")

        ip = page.get("ip")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            categories.append(f"IP observed: {ip}")

    categories.insert(0, f"Scans observed: {len(hits)}")

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious_count,
        suspicious=0,
        harmless=len(hits) - malicious_count,
        undetected=0,
        total=len(hits),
        reputation=None,
        categories=categories,
        threat_names=[],
        permalink=f"https://urlscan.io/search/#domain%3A{quote(domain)}",
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)


# ==========================================
# IP
# ==========================================

def lookup_ip(ip, api_key):
    """
    Look up an IP's urlscan.io scan history.

    Same aggregation approach as lookup_domain(). ASN / organization /
    country come from the most recent hit's `page` block — urlscan
    doesn't provide a CIDR/network value, so IPContext.network is left
    unset rather than guessed.
    """

    ioc = Ioc(value=ip, type=IocType.IP)

    data, err = _search(f'page.ip:"{ip}"', api_key)
    if err:
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=False, error=err)

    hits = (data.get("results", []) or [])[:_MAX_AGGREGATED_HITS]

    if not hits:
        result = ThreatIntelResult(ioc=ioc)
        return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)

    malicious_count = 0
    categories = []
    seen_domains = set()

    for hit in hits:
        is_malicious, _score, _cats = _overall_verdict(hit)
        if is_malicious:
            malicious_count += 1

        domain = (hit.get("page", {}) or {}).get("domain")
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            categories.append(f"Domain observed: {domain}")

    categories.insert(0, f"Scans observed: {len(hits)}")

    top_page = hits[0].get("page", {}) or {}

    reputation = ReputationFinding(
        provider=PROVIDER_NAME,
        malicious=malicious_count,
        suspicious=0,
        harmless=len(hits) - malicious_count,
        undetected=0,
        total=len(hits),
        reputation=None,
        categories=categories,
        threat_names=[],
        permalink=f"https://urlscan.io/search/#page.ip%3A{quote(ip)}",
    )

    ip_context = IPContext(
        asn=top_page.get("asn"),
        organization=top_page.get("asnname"),
        country=top_page.get("country"),
        network=None,
    )

    result = ThreatIntelResult(ioc=ioc, reputation=reputation, ip_context=ip_context)
    return ProviderResult(provider=PROVIDER_NAME, ioc=ioc, success=True, data=result)