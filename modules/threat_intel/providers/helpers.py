# modules/threat_intel/providers/helpers.py
"""
Shared HTTP and normalization helpers for threat intelligence providers.

This module consolidates duplicated helper code across multiple providers
(AbuseIPDB, OTX, URLScan, VirusTotal, RDAP, WHOIS) to reduce maintenance
burden and ensure consistent error handling.
"""

import logging

import requests

from modules.threat_intel.models import LookupError

log = logging.getLogger(__name__)


# ==========================================
# HTTP HEADERS
# ==========================================

def make_api_key_header(api_key, header_name):
    """
    Build a simple single-header dict with the given API key.
    
    Args:
        api_key (str): The API key value.
        header_name (str): The header name (e.g., "X-OTX-API-KEY", "Key").
    
    Returns:
        dict: Header dict with api_key, or empty dict if api_key is None/falsy.
    """
    return {header_name: api_key} if api_key else {}


# ==========================================
# HTTP REQUEST WITH STANDARD ERROR HANDLING
# ==========================================

def http_get_json(url, headers=None, params=None, timeout=20, provider_name="Provider"):
    """
    Perform a GET request with standard HTTP error handling and JSON parsing.
    
    Maps common HTTP status codes to LookupError enum values and handles
    JSON parsing failures consistently across all providers.
    
    Args:
        url (str): The endpoint URL.
        headers (dict): Request headers (optional).
        params (dict): Query parameters (optional).
        timeout (int): Request timeout in seconds (default 20).
        provider_name (str): Provider name for log messages.
    
    Returns:
        tuple: (json_dict, LookupError) — exactly one is None.
               On success: (parsed_json, None)
               On error: (None, LookupError.*)
    """

    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)

    except requests.exceptions.Timeout:
        return None, LookupError.NETWORK_ERROR

    except requests.exceptions.RequestException as e:
        log.error(f"{provider_name} request failed: {e}")
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
        log.error(f"{provider_name} response JSON parse failed: {e}")
        return None, LookupError.PARSE_ERROR