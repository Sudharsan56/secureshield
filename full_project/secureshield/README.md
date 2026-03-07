# 🛡️ SecureShield

**Lightweight, modular Python library for real-time web attack detection.**

SecureShield analyzes incoming URLs (and optionally headers/bodies) to detect and block common web attacks — including SQL Injection, XSS, Path Traversal, Command Injection, and more — before they reach your application logic.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PyPI version](https://img.shields.io/badge/pypi-1.0.0-orange.svg)](https://pypi.org/project/secureshield/)

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔍 Attack Detection | SQL Injection, XSS, Path Traversal, Command Injection, Open Redirect, LDAP/XXE Injection |
| 📝 Auto Logging | Logs attacks with timestamp, URL, and type to CSV or TXT |
| 📊 Report Generation | One-call summary report of all detected threats |
| ⚙️ Configurable | Custom log file paths, formats, and enable/disable toggle |
| 🔌 Framework Agnostic | Works with Flask, Django, FastAPI, or any Python web framework |
| 🪶 Zero Dependencies | Pure Python standard library — no external packages required |
| 🧩 Extensible | Add new attack patterns in `patterns.py` without touching core logic |

---

## 📦 Installation

### From PyPI (once published)
```bash
pip install secureshield
```

### From source
```bash
git clone https://github.com/yourname/secureshield.git
cd secureshield
pip install .
```

---

## 🚀 Quick Start

```python
from secureshield import scan_url

url = "https://mysite.com/search?q=1' OR '1'='1"
attack = scan_url(url)

if attack:
    print(f"⚠️  Attack detected: {attack}")
    # → "⚠️  Attack detected: SQL Injection"
else:
    print("✅ URL is clean")
```

---

## 🔌 Framework Integration

### Flask

```python
from secureshield import scan_url
from flask import Flask, request, abort

app = Flask(__name__)

@app.before_request
def protect():
    attack = scan_url(request.url)
    if attack:
        return f"⚠️ SecureShield Blocked Attack: {attack}", 403
```

### Django (Middleware)

```python
# myapp/middleware.py
from secureshield import scan_url

class SecureShieldMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        attack = scan_url(request.build_absolute_uri())
        if attack:
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden(f"⚠️ SecureShield Blocked: {attack}")
        return self.get_response(request)
```

```python
# settings.py
MIDDLEWARE = [
    "myapp.middleware.SecureShieldMiddleware",
    # ... other middleware
]
```

### FastAPI

```python
from secureshield import scan_url
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.middleware("http")
async def protect(request: Request, call_next):
    attack = scan_url(str(request.url))
    if attack:
        return JSONResponse(
            {"error": f"SecureShield Blocked: {attack}"},
            status_code=403
        )
    return await call_next(request)
```

### Scanning Headers & Body (Advanced)

For POST requests and API endpoints, use `scan_request` to inspect headers and body too:

```python
from secureshield import scan_request
from flask import Flask, request

app = Flask(__name__)

@app.before_request
def protect():
    attack = scan_request(
        method=request.method,
        url=request.url,
        headers=dict(request.headers),
        body=request.get_data(as_text=True),
    )
    if attack:
        return f"⚠️ SecureShield Blocked: {attack}", 403
```

---

## ⚙️ Configuration

Configure logging behavior at application startup:

```python
from secureshield import configure

configure(
    log_file="/var/log/secureshield/attacks.csv",  # custom path
    log_format="csv",   # "csv" (default) or "txt"
    log_enabled=True,   # set False to disable logging entirely
)
```

---

## 📊 Report Generation

```python
from secureshield import generate_report

# Print to console
print(generate_report())

# Save to file
generate_report(output_path="/var/log/secureshield/report.txt")
```

**Example output:**
```
============================================================
       SECURESHIELD ATTACK REPORT
============================================================
  Total Attacks Detected : 14
  Log File               : secureshield_attacks.csv

  Attack Breakdown:
    • SQL Injection              9 incident(s)
    • XSS                        3 incident(s)
    • Path Traversal             2 incident(s)

  Recent Entries (last 10):
------------------------------------------------------------
  [2024-11-01 14:22:03 UTC] SQL Injection — https://mysite.com/search?q=1'+OR+'1'='1
  [2024-11-01 14:23:55 UTC] XSS — https://mysite.com/page?x=<script>alert(1)</script>
============================================================
```

---

## 📁 CSV Log Format

Attacks are automatically saved to `secureshield_attacks.csv`:

```csv
timestamp,attack_type,url,notes
2024-11-01 14:22:03 UTC,SQL Injection,https://mysite.com/?id=1' OR '1'='1,
2024-11-01 14:23:55 UTC,XSS,https://mysite.com/?q=<script>alert(1)</script>,
```

---

## 🧩 Extending with New Patterns

Add custom detection rules by editing `secureshield/patterns.py`:

```python
ATTACK_PATTERNS["Custom Attack"] = [
    r"your-regex-pattern-here",
    r"another-pattern",
]
```

The core scanner automatically picks up all patterns in this dictionary — no other changes needed.

---

## 📐 Library Structure

```
secureshield/
├── secureshield/
│   ├── __init__.py       # Public API: scan_url, scan_request, configure, generate_report
│   ├── core.py           # scan_url() and scan_request() logic
│   ├── patterns.py       # All regex attack pattern definitions
│   └── report.py         # Logging and report generation
├── tests/
│   └── test_secureshield.py
├── pyproject.toml
├── setup.py
└── README.md
```

---

## 🔬 Detected Attack Types

| Attack Type | Example Pattern |
|---|---|
| SQL Injection | `' OR '1'='1`, `UNION SELECT`, `; DROP TABLE` |
| XSS | `<script>`, `onerror=`, `javascript:` |
| Path Traversal | `../../etc/passwd`, `%2e%2e%2f` |
| Command Injection | `; ls -la`, `\| bash`, `` `whoami` `` |
| Open Redirect | `redirect=https://evil.com` |
| LDAP Injection | `*)(uid=*))(|(uid=*` |
| XXE Injection | `<!ENTITY`, `SYSTEM "file://"` |

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install pytest

# Run all tests
pytest tests/ -v
```

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Add your attack patterns to `secureshield/patterns.py`
3. Add corresponding tests to `tests/test_secureshield.py`
4. Submit a pull request

---

> ⚠️ **Note:** SecureShield is a heuristic-based detection layer and is not a replacement for a full WAF or security audit. Always combine it with HTTPS, input validation, parameterized queries, and regular security reviews.
