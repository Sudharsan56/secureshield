# 🛡️ SecureShield

> **Lightweight Python library for real-time web attack detection.**  
> Zero dependencies · Production-ready · Flask/Django/FastAPI compatible

---

## 📁 Repository Structure

```
secureshield/                 ← The pip-installable Python library
├── secureshield/
│   ├── __init__.py
│   ├── core.py               ← scan_url() and scan_request()
│   ├── patterns.py           ← Attack regex patterns (extendable)
│   └── report.py             ← CSV/TXT logging + generate_report()
├── tests/
├── pyproject.toml
├── setup.py
└── README.md

demo_app/                     ← Live Flask demo (run locally or deploy)
├── app.py                    ← Flask web server
├── templates/
│   ├── index.html            ← Live URL scanner UI
│   ├── blocked.html          ← Attack blocked page
│   └── report.html           ← Attack log viewer
├── requirements.txt
└── README.md
```

---

## ⚡ Install the Library

```bash
pip install secureshield
```

## 🔌 Use in Your Website (4 lines)

```python
from secureshield import scan_url
from flask import Flask, request

app = Flask(__name__)

@app.before_request
def protect():
    attack = scan_url(request.url)
    if attack:
        return f"⚠️ SecureShield Blocked: {attack}", 403
```

---

## 🎮 Run the Demo App

```bash
cd demo_app
pip install flask
python app.py
# → Open http://localhost:5000
```

---

## 🔍 What It Detects

| Attack | Example |
|---|---|
| 💉 SQL Injection | `' OR '1'='1`, `UNION SELECT` |
| ⚡ XSS | `<script>alert(1)</script>`, `onerror=` |
| 📂 Path Traversal | `../../etc/passwd` |
| 💻 Command Injection | `; ls -la`, `\| bash` |
| ↪️ Open Redirect | `redirect=https://evil.com` |
| 🗂️ LDAP / XXE | `*)(uid=*)`, `<!ENTITY` |

---

## 📊 Auto Logging

Attacks are logged automatically to `secureshield_attacks.csv`:

```csv
timestamp,attack_type,url,notes
2024-11-01 14:22:03 UTC,SQL Injection,https://site.com/?id=1' OR '1'='1,
```

---

## 📜 License

MIT — free to use, modify, and distribute.

---

**Made with 🛡️ by [Your Name]**
