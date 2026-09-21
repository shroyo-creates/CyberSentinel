# CyberSentinel

A lightweight Web Application Firewall (WAF) built with Flask that detects
and blocks SQL Injection, XSS, and Path Traversal attacks in real time,
with a dashboard to visualize caught threats. Built as a college
mini-project - simple, readable, and fully explainable.

## How it works

1. `app.py` runs a small "vulnerable" demo app with three attack surfaces:
   a login form, a search box, and a file-fetch endpoint.
2. `waf.py` registers a Flask `before_request` hook - this is middleware
   that runs **before every single route handler**, for every request.
3. On each request, the WAF checks the URL path, every query-string
   parameter, and every submitted form field against regex rules for
   SQL Injection, XSS, and Path Traversal.
4. If anything matches, the WAF:
   - logs the attempt to `logs/waf_log.json` (timestamp, attack type,
     matched pattern, payload, source IP, blocked URL), and
   - returns an HTTP 403 "Blocked by WAF" page **without ever running**
     the route's own code.
5. If the request is clean, the WAF does nothing and Flask continues to
   the normal route handler.
6. `/dashboard` reads `logs/waf_log.json` and shows every blocked attempt
   in a table (most recent first), plus a count summary per attack type.

## Project structure

```
CyberSentinel/
├── app.py              # The demo app: routes for /, /login, /search, /fetch, /dashboard
├── waf.py               # WAF middleware: detection rules, scanning, logging
├── requirements.txt
├── test_attacks.sh      # curl commands that demonstrate each attack type being blocked
├── logs/
│   └── waf_log.json     # JSON "database" of blocked attempts (auto-created/updated)
├── static/
│   └── style.css
└── templates/
    ├── base.html         # shared layout + nav
    ├── index.html
    ├── login.html
    ├── search.html
    ├── fetch.html
    ├── blocked.html      # 403 page shown when the WAF blocks a request
    └── dashboard.html    # attack log table + summary counts
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The app runs at http://localhost:5000

## Trying it out

- Visit http://localhost:5000 and try the login form, search box, and
  fetch-file endpoint with normal input - everything should work fine.
- Then try the same pages with malicious input, e.g.:
  - Login username: `admin' OR '1'='1`
  - Search: `<script>alert(1)</script>`
  - Fetch file: `../../../../etc/passwd`
- Each of these should be rejected with a "Blocked by WAF" 403 page.
- Visit http://localhost:5000/dashboard to see every blocked attempt
  logged, with counts per attack type.

## Automated test script

With the server running, in another terminal:

```bash
./test_attacks.sh
```

This fires one clean baseline request plus two sample payloads for each
of the three attack types (SQL Injection, XSS, Path Traversal) and
prints the HTTP status code returned for each. The malicious ones
should all come back `403`; the clean one should come back `200`.
Afterwards, check `/dashboard` to see them all logged.

## Detection rules (waf.py)

| Attack Type      | Example patterns checked                                   |
|-------------------|--------------------------------------------------------------|
| SQL Injection      | `' OR 1=1`, `UNION SELECT`, `DROP TABLE`, `--`, `;`         |
| XSS                | `<script>`, `onerror=`, `onload=`, `javascript:`, `<img src=x onerror=...>` |
| Path Traversal     | `../`, `..\`, `%2e%2e%2f`, `/etc/passwd`                    |

These are plain regular expressions, intentionally simple so they're
easy to read and explain. A production-grade WAF (e.g. OWASP
ModSecurity Core Rule Set) uses far more sophisticated detection -
this project is meant to demonstrate the *concept* of request
interception, pattern-based detection, and logging.

## Notes / limitations (good to mention when presenting)

- No real database - all input is echoed back or simulated; no queries
  are actually executed and no files are actually read.
- Regex-based detection can have false positives (e.g. a search for
  `it's a nice day` contains an apostrophe) and false negatives
  (creative attackers can often bypass regex-only filters). This is a
  known trade-off of signature-based WAFs and is worth discussing in
  a report/presentation.
- The JSON log file is not safe for concurrent writes at high scale;
  it's used here instead of a database to keep the project dependency-free
  and easy to inspect/explain.
