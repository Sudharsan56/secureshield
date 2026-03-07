"""
SecureShield - Flask Demo App
==============================
A simple web app to demonstrate how SecureShield detects
and blocks web attacks in real-time.

Run:
    pip install flask
    python app.py

Then open: http://localhost:5000
"""

import sys
import os

# Allow importing secureshield from the parent folder (for demo purposes)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'secureshield'))

from secureshield import scan_url, scan_request, configure, generate_report
from flask import Flask, request, render_template, jsonify

# ── Configure SecureShield logging ──────────────────────────────────────────
configure(
    log_file="attack_log.csv",
    log_format="csv",
    log_enabled=True,
)

app = Flask(__name__)

# ── Security Middleware ──────────────────────────────────────────────────────
@app.before_request
def protect():
    """Scan every incoming request before it reaches any route."""
    attack = scan_request(
        method=request.method,
        url=request.url,
        headers=dict(request.headers),
        body=request.get_data(as_text=True),
    )
    if attack:
        return render_template("blocked.html", attack=attack, url=request.url), 403


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """API endpoint — scan a URL submitted from the test form."""
    data = request.get_json()
    test_url = data.get("url", "")
    result = scan_url(test_url, log=True)
    return jsonify({
        "url": test_url,
        "attack": result,
        "safe": result is None,
    })


@app.route("/report")
def report():
    """Show the attack log report."""
    report_text = generate_report()
    return render_template("report.html", report=report_text)


@app.route("/api/status")
def status():
    return jsonify({"status": "SecureShield Active", "version": "1.0.0"})


# ── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
