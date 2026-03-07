"""
SecureShield - Core Detection Module
Provides real-time detection of web attacks in URLs.
"""

import re
from urllib.parse import unquote, urlparse
from typing import Optional

from .report import log_attack
from .patterns import ATTACK_PATTERNS


def _normalize_url(url: str) -> str:
    """Decode and normalize URL for consistent pattern matching."""
    try:
        decoded = unquote(url)
        return decoded.lower()
    except Exception:
        return url.lower()


def scan_url(url: str, log: bool = True) -> Optional[str]:
    """
    Analyze a URL string for common web attack patterns.

    Detects:
        - SQL Injection
        - Cross-Site Scripting (XSS)
        - Path Traversal
        - Command Injection
        - Open Redirect

    Args:
        url (str): The full URL string to analyze.
        log (bool): Whether to log the detected attack to the report file.
                    Defaults to True.

    Returns:
        str | None: The name of the detected attack type (e.g., "SQL Injection"),
                    or None if no threat is found.

    Example:
        >>> from secureshield import scan_url
        >>> result = scan_url("https://example.com/search?q=1' OR '1'='1")
        >>> print(result)  # "SQL Injection"
    """
    if not url or not isinstance(url, str):
        return None

    normalized = _normalize_url(url)

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, normalized, re.IGNORECASE):
                if log:
                    log_attack(url=url, attack_type=attack_type)
                return attack_type

    return None


def scan_request(method: str, url: str, headers: Optional[dict] = None,
                 body: Optional[str] = None, log: bool = True) -> Optional[str]:
    """
    Extended scan that checks URL, headers, and request body.

    Args:
        method (str): HTTP method (GET, POST, etc.).
        url (str): The request URL.
        headers (dict, optional): Request headers to scan.
        body (str, optional): Request body to scan.
        log (bool): Whether to log detected attacks.

    Returns:
        str | None: Detected attack type or None.

    Example:
        >>> attack = scan_request("POST", "/login", body="user=admin'--")
        >>> print(attack)  # "SQL Injection"
    """
    # Scan URL first
    result = scan_url(url, log=log)
    if result:
        return result

    # Scan headers
    if headers:
        for key, value in headers.items():
            combined = f"{key}={value}"
            result = scan_url(combined, log=log)
            if result:
                return result

    # Scan body
    if body:
        result = scan_url(body, log=log)
        if result:
            return result

    return None
