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

from flask import Flask, request, render_template, redirect, url_for, session, jsonify

import settings
from database import init_db, check_login_vulnerable, check_login_safe
from waf import init_waf, get_attack_logs
from traffic import get_traffic_stats

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
    """Decorator for normal pages: redirect to /admin/login unless logged in."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def api_admin_required(view):
    """
    Decorator for /api/* routes: a redirect makes no sense for a fetch()
    call, so return a JSON 401 instead. The React dashboard checks for
    this and sends the browser to /admin/login itself.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def build_dashboard_payload():
    """
    Gather everything the dashboard needs: overall traffic stats (total
    requests inspected / blocked / block rate, and a minute-by-minute
    timeline of allowed vs blocked), the raw attack log, a per-attack-type
    summary, the top matched regex patterns, the top source IPs, and the
    latest evaluate_waf.py benchmark (if one has been run). Used by both
    the /dashboard page (admin_required) and the /api/dashboard JSON
    endpoint (api_admin_required) that the React app polls.
    """
    logs = get_attack_logs()
    traffic = get_traffic_stats()

    summary = {"SQL Injection": 0, "XSS": 0, "Path Traversal": 0}
    for entry in logs:
        attack_type = entry.get("attack_type")
        if attack_type in summary:
            summary[attack_type] += 1
    attack_distribution = [{"name": name, "value": count} for name, count in summary.items()]

    # Which specific regex rule fires most often.
    pattern_counts = Counter(entry.get("matched_pattern", "unknown") for entry in logs)
    top_patterns = [{"pattern": pattern, "count": count} for pattern, count in pattern_counts.most_common(5)]

    # Top source IPs, e.g. [{"ip": "127.0.0.1", "count": 4}, ...]
    ip_counts = Counter(entry.get("source_ip", "unknown") for entry in logs)
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(5)]

    benchmark = None
    if os.path.exists(BENCHMARK_RESULTS_FILE):
        with open(BENCHMARK_RESULTS_FILE) as f:
            try:
                benchmark = json.load(f)
            except json.JSONDecodeError:
                benchmark = None

    return {
        "logs": logs,
        "summary": summary,
        "attack_distribution": attack_distribution,
        "top_patterns": top_patterns,
        "total": len(logs),
        "total_requests": traffic["total_requests"],
        "total_allowed": traffic["total_allowed"],
        "block_rate": traffic["block_rate"],
        "traffic_timeline": traffic["timeline"],
        "top_ips": top_ips,
        "benchmark": benchmark,
        "waf_enabled": settings.waf_enabled,
        "query_mode": settings.query_mode,
    }


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
    The WAF detection dashboard. This route only renders the page shell
    (templates/dashboard.html) - the actual data (attack log, summary,
    charts, benchmark) is fetched client-side by the React app from
    /api/dashboard, and refreshed automatically every few seconds.
    """
    return render_template("dashboard.html")


@app.route("/api/dashboard")
@api_admin_required
def api_dashboard():
    """JSON data source for the React dashboard. Polled every few seconds."""
    return jsonify(build_dashboard_payload())


@app.route("/api/admin/settings", methods=["POST"])
@api_admin_required
def api_admin_settings():
    """Toggle the demo switches described in settings.py, JSON in/out."""
    action = (request.get_json(silent=True) or {}).get("action")
    if action == "toggle_waf":
        settings.waf_enabled = not settings.waf_enabled
    elif action == "toggle_query_mode":
        settings.query_mode = "vulnerable" if settings.query_mode == "safe" else "safe"
    else:
        return jsonify({"error": "unknown action"}), 400

    return jsonify({"waf_enabled": settings.waf_enabled, "query_mode": settings.query_mode})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
