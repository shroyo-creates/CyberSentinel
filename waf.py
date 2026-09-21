"""
waf.py - The Web Application Firewall (WAF) logic.

This module is the "brain" of CyberSentinel. It does three jobs:

1.  Define regex patterns that describe what a SQL Injection, XSS, or
    Path Traversal attack usually looks like.
2.  Scan every incoming Flask request (URL path + query string + form
    fields) against those patterns BEFORE the request reaches any
    route handler (login, search, fetch, ...).
3.  If something matches, log it to a JSON file and reject the request
    with an HTTP 403 response. If nothing matches, do nothing and let
    Flask continue processing the request normally.

Everything here is intentionally simple (regex matching) so it is easy
to explain in a college mini-project. A production WAF would be far
more sophisticated (parsing, allow-lists, WAF rule engines like
ModSecurity/OWASP CRS, etc.).
"""

import json
import os
import re
from datetime import datetime, timezone

from flask import request, render_template

# ---------------------------------------------------------------------------
# 1. DETECTION RULES
# ---------------------------------------------------------------------------
# Each attack type maps to a list of (regex_pattern, human_readable_name)
# tuples. We keep the human-readable name so the dashboard/log can show
# something friendlier than a raw regex string.
#
# re.IGNORECASE is applied when we compile these, so "UNION select" and
# "union SELECT" are both caught.

SQLI_PATTERNS = [
    (r"'\s*or\s*'?\s*\d\s*'?\s*=\s*'?\s*\d", "' OR 1=1 style tautology"),
    (r"\bor\b\s+\d+\s*=\s*\d+", "OR 1=1 tautology"),
    (r"\bunion\b\s+\bselect\b", "UNION SELECT"),
    (r"\bdrop\b\s+\btable\b", "DROP TABLE"),
    (r"--", "SQL inline comment (--)"),
    (r";", "Statement terminator (;)"),
]

XSS_PATTERNS = [
    (r"<script[^>]*>", "<script> tag"),
    (r"onerror\s*=", "onerror= event handler"),
    (r"onload\s*=", "onload= event handler"),
    (r"javascript:", "javascript: URI"),
    (r"<img[^>]+onerror\s*=", "<img src=x onerror=...>"),
]

PATH_TRAVERSAL_PATTERNS = [
    (r"\.\./", "../ directory traversal"),
    (r"\.\.\\", "..\\ directory traversal"),
    (r"%2e%2e%2f", "URL-encoded ../ (%2e%2e%2f)"),
    (r"%2e%2e/", "URL-encoded .. (%2e%2e/)"),
    (r"/etc/passwd", "/etc/passwd access attempt"),
]

# Group everything together so we can loop over it in one place.
ATTACK_RULES = {
    "SQL Injection": SQLI_PATTERNS,
    "XSS": XSS_PATTERNS,
    "Path Traversal": PATH_TRAVERSAL_PATTERNS,
}

# Pre-compile every pattern once at import time (faster than recompiling
# the same regex on every single request).
COMPILED_RULES = {
    attack_type: [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in patterns]
    for attack_type, patterns in ATTACK_RULES.items()
}

# ---------------------------------------------------------------------------
# 2. LOGGING
# ---------------------------------------------------------------------------
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "waf_log.json")


def _ensure_log_file():
    """Make sure logs/waf_log.json exists and contains a JSON list."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)


def log_attack(attack_type, matched_pattern, payload, source_ip, blocked_url):
    """Append one blocked-attack record to the JSON log file."""
    _ensure_log_file()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "matched_pattern": matched_pattern,
        "payload": payload,
        "source_ip": source_ip,
        "blocked_url": blocked_url,
    }

    with open(LOG_FILE, "r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            # File was empty/corrupted - start fresh instead of crashing.
            logs = []

    logs.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

    return entry


def get_attack_logs():
    """Return all logged attacks, most recent first (for the dashboard)."""
    _ensure_log_file()
    with open(LOG_FILE, "r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            logs = []

    # Sort by timestamp descending (newest attack shown first).
    logs.sort(key=lambda entry: entry.get("timestamp", ""), reverse=True)
    return logs


# ---------------------------------------------------------------------------
# 3. SCANNING
# ---------------------------------------------------------------------------
def scan_value(value):
    """
    Check a single string value against every attack pattern.

    Returns a tuple (attack_type, matched_pattern_label) on the first
    match found, or None if the value looks clean.
    """
    if not value:
        return None

    for attack_type, compiled_patterns in COMPILED_RULES.items():
        for pattern, label in compiled_patterns:
            if pattern.search(value):
                return attack_type, label

    return None


def get_request_inputs(req):
    """
    Collect everything about the request that a user could control:
    the URL path itself, every query-string parameter, and every
    submitted form field. Returns a dict of {source_label: value}.
    """
    inputs = {"URL path": req.path}

    for key, value in req.args.items():
        inputs[f"query param '{key}'"] = value

    for key, value in req.form.items():
        inputs[f"form field '{key}'"] = value

    return inputs


def inspect_request(req):
    """
    Run every user-controlled input from the request through scan_value().

    Returns a dict describing the attack (attack_type, matched_pattern,
    payload, source) on the first match, or None if the request is clean.
    """
    for source, value in get_request_inputs(req).items():
        result = scan_value(value)
        if result:
            attack_type, matched_pattern = result
            return {
                "attack_type": attack_type,
                "matched_pattern": matched_pattern,
                "payload": value,
                "source": source,
            }
    return None


# ---------------------------------------------------------------------------
# 4. FLASK MIDDLEWARE
# ---------------------------------------------------------------------------
def init_waf(app):
    """
    Wire the WAF into a Flask app.

    app.before_request runs this function before ANY route handler, for
    EVERY request the server receives - that's what makes this "middleware":
    it sits in front of the real application logic and can stop a request
    from ever reaching it.
    """

    @app.before_request
    def waf_before_request():
        # Don't inspect requests for static assets (CSS/JS/images) - they
        # aren't user input and would just waste CPU cycles.
        if request.path.startswith("/static/"):
            return None

        detection = inspect_request(request)
        if detection is None:
            # Nothing suspicious found - let Flask continue to the route.
            return None

        # Something matched an attack pattern - log it and block the request.
        entry = log_attack(
            attack_type=detection["attack_type"],
            matched_pattern=detection["matched_pattern"],
            payload=detection["payload"],
            source_ip=request.remote_addr,
            blocked_url=request.full_path if request.query_string else request.path,
        )

        return (
            render_template(
                "blocked.html",
                attack_type=entry["attack_type"],
                matched_pattern=entry["matched_pattern"],
                payload=entry["payload"],
                source=detection["source"],
            ),
            403,
        )
