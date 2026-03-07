"""
SecureShield - Report & Logging Module
Handles logging of detected attacks to TXT and CSV files,
and provides report generation utilities.
"""

import csv
import os
from datetime import datetime
from typing import Literal, Optional

# Default log file paths (can be overridden via configure())
_config = {
    "log_file": "secureshield_attacks.csv",
    "log_format": "csv",     # "csv" or "txt"
    "log_enabled": True,
}


def configure(
    log_file: Optional[str] = None,
    log_format: Optional[Literal["csv", "txt"]] = None,
    log_enabled: Optional[bool] = None,
) -> None:
    """
    Configure SecureShield logging behavior.

    Args:
        log_file (str, optional): Path to the log output file.
                                  Default: "secureshield_attacks.csv"
        log_format (str, optional): Output format — "csv" or "txt".
                                    Default: "csv"
        log_enabled (bool, optional): Enable or disable logging entirely.
                                      Default: True

    Example:
        >>> from secureshield import configure
        >>> configure(log_file="/var/log/attacks.csv", log_format="csv")
    """
    if log_file is not None:
        _config["log_file"] = log_file
    if log_format is not None:
        if log_format not in ("csv", "txt"):
            raise ValueError("log_format must be 'csv' or 'txt'")
        _config["log_format"] = log_format
    if log_enabled is not None:
        _config["log_enabled"] = log_enabled


def log_attack(url: str, attack_type: str, extra: Optional[str] = None) -> None:
    """
    Log a detected attack to the configured report file.

    Args:
        url (str): The URL where the attack was detected.
        attack_type (str): The type of attack detected.
        extra (str, optional): Additional context or notes.

    The log entry includes:
        - Timestamp (ISO 8601)
        - Attack type
        - URL
        - Extra notes (if provided)
    """
    if not _config["log_enabled"]:
        return

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log_path = _config["log_file"]
    fmt = _config["log_format"]

    try:
        if fmt == "csv":
            _write_csv(log_path, timestamp, attack_type, url, extra or "")
        else:
            _write_txt(log_path, timestamp, attack_type, url, extra or "")
    except OSError as e:
        # Fail silently — logging should never crash the host application
        print(f"[SecureShield] Warning: Could not write log — {e}")


def _write_csv(path: str, timestamp: str, attack_type: str,
               url: str, extra: str) -> None:
    """Append an attack entry to a CSV file."""
    file_exists = os.path.isfile(path)
    with open(path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "attack_type", "url", "notes"])
        writer.writerow([timestamp, attack_type, url, extra])


def _write_txt(path: str, timestamp: str, attack_type: str,
               url: str, extra: str) -> None:
    """Append a human-readable attack entry to a TXT file."""
    with open(path, mode="a", encoding="utf-8") as f:
        f.write(f"[{timestamp}]\n")
        f.write(f"  Attack Type : {attack_type}\n")
        f.write(f"  URL         : {url}\n")
        if extra:
            f.write(f"  Notes       : {extra}\n")
        f.write("-" * 60 + "\n")


def generate_report(output_path: Optional[str] = None) -> str:
    """
    Generate a human-readable summary report from the current log file.

    Args:
        output_path (str, optional): Path to save the report.
                                     If None, returns the report as a string.

    Returns:
        str: The formatted report content.

    Example:
        >>> from secureshield.report import generate_report
        >>> print(generate_report())
    """
    log_path = _config["log_file"]

    if not os.path.isfile(log_path):
        return "No attacks have been logged yet."

    entries = []
    fmt = _config["log_format"]

    if fmt == "csv" or log_path.endswith(".csv"):
        with open(log_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entries.append(row)
    else:
        with open(log_path, mode="r", encoding="utf-8") as f:
            raw = f.read()
        return raw  # TXT logs are already human-readable

    if not entries:
        return "No attacks have been logged yet."

    # Build summary
    attack_counts: dict = {}
    for entry in entries:
        atype = entry.get("attack_type", "Unknown")
        attack_counts[atype] = attack_counts.get(atype, 0) + 1

    lines = [
        "=" * 60,
        "       SECURESHIELD ATTACK REPORT",
        "=" * 60,
        f"  Total Attacks Detected : {len(entries)}",
        f"  Log File               : {log_path}",
        "",
        "  Attack Breakdown:",
    ]
    for atype, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        lines.append(f"    • {atype:<25} {count} incident(s)")

    lines += [
        "",
        "  Recent Entries (last 10):",
        "-" * 60,
    ]
    for entry in entries[-10:]:
        lines.append(
            f"  [{entry.get('timestamp', 'N/A')}] "
            f"{entry.get('attack_type', 'N/A')} — {entry.get('url', 'N/A')[:80]}"
        )

    lines.append("=" * 60)
    report = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    return report


def clear_log() -> None:
    """
    Delete the current log file to start fresh.

    Use with caution — this action is irreversible.

    Example:
        >>> from secureshield.report import clear_log
        >>> clear_log()
    """
    log_path = _config["log_file"]
    if os.path.isfile(log_path):
        os.remove(log_path)
