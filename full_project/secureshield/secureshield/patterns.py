"""
SecureShield - Attack Pattern Definitions
Centralized regex patterns for detecting various web attack types.
Extend this file to add new detection rules.
"""

# Each key is an attack type name; values are lists of regex patterns.
# Patterns are matched case-insensitively against the normalized (decoded, lowercased) URL.

ATTACK_PATTERNS: dict = {

    "SQL Injection": [
        # Classic OR/AND bypass
        r"(\b(or|and)\b\s*[\'\"]?\s*\d+\s*=\s*\d+)",
        # Comment-based injection
        r"(--|#|/\*|\*/)",
        # UNION-based injection
        r"\bunion\b.{0,20}\bselect\b",
        # Common SQL keywords in suspicious context
        r"(;\s*(drop|alter|truncate|delete|insert|update)\s+\b)",
        # Stacked queries
        r";\s*(select|exec|execute|declare)\b",
        # Blind injection patterns
        r"\bwaitfor\s+delay\b",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\(",
        # Quote-based injection attempts
        r"['\"](\s*(or|and)\s*)['\"]",
        # Common login bypass
        r"'\s*or\s*'1'\s*=\s*'1",
        r"admin'--",
        r"'\s*;\s*--",
    ],

    "XSS": [
        # Script tags
        r"<\s*script[\s>]",
        r"</\s*script\s*>",
        # Event handlers
        r"\bon\w+\s*=",
        # JavaScript protocol
        r"javascript\s*:",
        r"vbscript\s*:",
        # Data URIs with scripts
        r"data\s*:\s*text/html",
        # Common XSS vectors
        r"<\s*iframe[\s>]",
        r"<\s*img[^>]+src\s*=\s*['\"]?\s*javascript",
        r"<\s*svg[^>]*>.*<\s*script",
        r"expression\s*\(",
        r"document\s*\.\s*(cookie|write|location)",
        r"window\s*\.\s*(location|open)",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        # Encoded XSS
        r"&#x[0-9a-f]+;",
        r"%3cscript",
        r"%3e",
    ],

    "Path Traversal": [
        # Unix-style traversal
        r"\.\./",
        r"\.\.%2f",
        r"\.\.%5c",
        # Windows-style traversal
        r"\.\.[/\\]",
        r"%2e%2e[/\\%]",
        # Absolute path access
        r"(^|[?&=/])/etc/(passwd|shadow|hosts)",
        r"(^|[?&=/])/proc/",
        r"(^|[?&=/])c:[/\\]windows",
        # Null byte injection
        r"%00",
        r"\x00",
    ],

    "Command Injection": [
        # Shell metacharacters in parameter values
        r"[;&|`$]\s*(ls|cat|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby)",
        # Pipe to shell
        r"\|\s*(bash|sh|cmd|powershell)",
        # Backtick execution
        r"`[^`]+`",
        # Common shell commands
        r";\s*(wget|curl)\s+http",
        r"\$\(.*\)",
        # Windows command injection
        r"cmd\.exe",
        r"powershell",
    ],

    "Open Redirect": [
        # Redirect parameter patterns
        r"(redirect|return|next|url|dest|destination|continue|target)\s*=\s*https?://",
        # Protocol-relative redirect
        r"(redirect|return|next|url)\s*=\s*//[a-z0-9]",
        # Encoded redirect
        r"(redirect|return|next|url)\s*=\s*%68%74%74%70",
    ],

    "LDAP Injection": [
        r"\*\)\s*\(",
        r"\(\|\(",
        r"\(\&\(",
        r"[)(|&*\\].*ldap",
    ],

    "XML/XXE Injection": [
        r"<!entity",
        r"<!doctype[^>]*\[",
        r"system\s+['\"]file://",
        r"SYSTEM\s+['\"]",
    ],

}
