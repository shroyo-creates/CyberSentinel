"""
app.py - The "vulnerable" demo application.

This is a small Flask app with three classic attack surfaces:

  * /login  - a login form (username + password)
  * /search - a search box
  * /fetch  - a file-fetch endpoint (?file=report.txt)

On purpose, this app does NOT do any input validation of its own - it
just echoes back whatever the user sent. It exists only to give the WAF
(waf.py) something to protect. Because init_waf(app) below registers a
before_request hook, every request to these routes is checked by the
WAF BEFORE this file's route functions ever run.

Run with:  python app.py
Then visit http://localhost:5000
"""

from flask import Flask, request, render_template

from waf import init_waf, get_attack_logs

app = Flask(__name__)

# Attach the WAF middleware. From this point on, every incoming request
# is scanned by waf.py's before_request hook first.
init_waf(app)


@app.route("/")
def index():
    """Simple landing page with links to every demo endpoint."""
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    A fake login form. There is no real user database - we just show
    back what was submitted so you can see the WAF letting clean input
    through, and blocking malicious input before it ever gets here.
    """
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # NOTE: In a real app this would be checked against a database
        # (and the password would be hashed). This is a demo only.
        message = f"Login attempt received for username: '{username}'"
    return render_template("login.html", message=message)


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


@app.route("/dashboard")
def dashboard():
    """
    The WAF detection dashboard. Reads every blocked attack from the
    JSON log file and displays a table plus a per-attack-type count.
    """
    logs = get_attack_logs()

    summary = {"SQL Injection": 0, "XSS": 0, "Path Traversal": 0}
    for entry in logs:
        attack_type = entry.get("attack_type")
        if attack_type in summary:
            summary[attack_type] += 1

    return render_template(
        "dashboard.html",
        logs=logs,
        summary=summary,
        total=len(logs),
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
