"""
SecureShield
============
A lightweight Python library for real-time detection and blocking
of web attacks including SQL Injection, XSS, Path Traversal,
Command Injection, and more.

Quick Start:
    >>> from secureshield import scan_url
    >>> attack = scan_url("https://example.com?id=1' OR '1'='1")
    >>> if attack:
    ...     print(f"Attack detected: {attack}")

Flask Integration:
    from secureshield import scan_url
    from flask import Flask, request

    app = Flask(__name__)

    @app.before_request
    def protect():
        attack = scan_url(request.url)
        if attack:
            return f"⚠ SecureShield Blocked: {attack}", 403
"""

from .core import scan_url, scan_request
from .report import configure, generate_report, clear_log, log_attack

__version__ = "1.0.0"
__author__ = "SecureShield Contributors"
__license__ = "MIT"

__all__ = [
    "scan_url",
    "scan_request",
    "configure",
    "generate_report",
    "clear_log",
    "log_attack",
]
