"""
app.py - The "vulnerable" demo application.

This is a small Flask app with three classic attack surfaces:

  * /login  - a login form (username + password), backed by a real
              SQLite users table (see database.py)
  * /search - a search box
  * /fetch  - a file-fetch endpoint (?file=report.txt)

On purpose, most of this app does NOT do its own input validation - it
exists to give the WAF (waf.py) something to protect. Because
init_waf(app) below registers a before_request hook, every request to
these routes is checked by the WAF BEFORE this file's route functions
ever run (unless an admin has switched the WAF off from /admin/settings
for a demo - see settings.py).

/login is special: it's wired to settings.query_mode so you can show,
live, the difference between a vulnerable (string-built) SQL query and
a safe (parameterized) one - on top of the WAF layer.

Admin-only pages (/dashboard, /admin/settings) require logging in at
/admin/login first. The admin credentials below are hardcoded for this
classroom demo only - never do this in a real application.

Run with:  python app.py
Then visit http://localhost:5000
"""

import json
import os
from collections import Counter
from functools import wraps

from flask import Flask, request, render_template, redirect, url_for, session

import settings
from database import init_db, check_login_vulnerable, check_login_safe
from waf import init_waf, get_attack_logs

app = Flask(__name__)

# Needed for Flask's session cookie (admin login state). A fixed dev key
# is fine for a local classroom demo; a real deployment would load this
# from an environment variable instead.
app.secret_key = "cybersentinel-dev-secret-key-do-not-use-in-production"

# Hardcoded admin credentials - demo only. In a real app these would be
# hashed and stored in a database, not sitting here in plaintext.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "waf-admin123"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BENCHMARK_RESULTS_FILE = os.path.join(BASE_DIR, "dataset", "results.json")

# Attach the WAF middleware. From this point on, every incoming request
# is scanned by waf.py's before_request hook first (unless disabled).
init_waf(app)

# Make sure the demo SQLite database exists before any request uses it.
init_db()


def admin_required(view):
    """Decorator: redirect to /admin/login unless an admin is logged in."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    """Simple landing page with links to every demo endpoint."""
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login form backed by a real SQLite users table (database.py).

    settings.query_mode picks which query builder runs:
      - "safe"       -> parameterized query (recommended, default)
      - "vulnerable" -> raw f-string SQL (classic SQLi bug)

    Demo accounts: admin / admin123, alice / wonderland.
    """
    message = None
    executed_query = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if settings.query_mode == "vulnerable":
            row, executed_query = check_login_vulnerable(username, password)
        else:
            row, executed_query = check_login_safe(username, password)

        if row:
            message = f"Login SUCCESS - welcome back, '{row[0]}'!"
        else:
            message = "Login failed: invalid username or password."

    return render_template(
        "login.html",
        message=message,
        executed_query=executed_query,
        query_mode=settings.query_mode,
        waf_enabled=settings.waf_enabled,
    )


@app.route("/search")
def search():
    """A fake search box that just echoes the query back."""
    query = request.args.get("q", "")
    results = f"Showing results for: '{query}'" if query else None
    return render_template("search.html", results=results, query=query)


@app.route("/fetch")
def fetch():
    """
    A fake file-fetch endpoint, e.g. /fetch?file=report.txt

    In a real (broken) app, this might do something dangerous like
    open(f"/files/{filename}"), which is exactly what path-traversal
    payloads like ../../etc/passwd are designed to exploit. Here we
    only simulate it, since the WAF should stop the traversal payloads
    before this code ever runs.
    """
    filename = request.args.get("file", "")
    content = f"(Simulated) fetching file: '{filename}'" if filename else None
    return render_template("fetch.html", content=content, filename=filename)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Admin login gate for /dashboard and /admin/settings."""
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid admin credentials."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """Toggle the demo switches described in settings.py."""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "toggle_waf":
            settings.waf_enabled = not settings.waf_enabled
        elif action == "toggle_query_mode":
            settings.query_mode = "vulnerable" if settings.query_mode == "safe" else "safe"
        return redirect(url_for("admin_settings"))

    return render_template(
        "admin_settings.html",
        waf_enabled=settings.waf_enabled,
        query_mode=settings.query_mode,
    )


@app.route("/dashboard")
@admin_required
def dashboard():
    """
    The WAF detection dashboard. Reads every blocked attack from the
    JSON log file and displays a table, a per-attack-type count, a
    per-day timeline chart, a top-source-IP chart, and (if available)
    the latest dataset benchmark results from evaluate_waf.py.
    """
    logs = get_attack_logs()

    summary = {"SQL Injection": 0, "XSS": 0, "Path Traversal": 0}
    for entry in logs:
        attack_type = entry.get("attack_type")
        if attack_type in summary:
            summary[attack_type] += 1

    # --- Attacks-per-day timeline (plain CSS bar chart, no JS needed) ---
    day_counts = Counter(entry.get("timestamp", "")[:10] for entry in logs if entry.get("timestamp"))
    timeline = sorted(day_counts.items())  # chronological, e.g. [("2026-09-21", 6), ...]
    max_day_count = max((count for _, count in timeline), default=0)

    # --- Top source IPs ---
    ip_counts = Counter(entry.get("source_ip", "unknown") for entry in logs)
    top_ips = ip_counts.most_common(5)
    max_ip_count = max((count for _, count in top_ips), default=0)

    # --- Latest dataset benchmark results, if evaluate_waf.py has been run ---
    benchmark = None
    if os.path.exists(BENCHMARK_RESULTS_FILE):
        with open(BENCHMARK_RESULTS_FILE) as f:
            try:
                benchmark = json.load(f)
            except json.JSONDecodeError:
                benchmark = None

    return render_template(
        "dashboard.html",
        logs=logs,
        summary=summary,
        total=len(logs),
        timeline=timeline,
        max_day_count=max_day_count,
        top_ips=top_ips,
        max_ip_count=max_ip_count,
        benchmark=benchmark,
        waf_enabled=settings.waf_enabled,
        query_mode=settings.query_mode,
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
