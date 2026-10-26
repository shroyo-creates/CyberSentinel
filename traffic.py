"""
traffic.py - logs EVERY request to the protected demo routes, not just
the blocked ones.

waf.py's log_attack() only records attacks the WAF caught, which means
a dashboard built from it alone can never show the thing a real WAF
dashboard shows first: how much traffic came in, and what fraction of
it was malicious. This module fixes that by recording a lightweight
entry for every request to the public demo surface (/, /login, /search,
/fetch) - whether the WAF blocked it or not.

Admin/API/static routes are intentionally excluded (see PUBLIC_ROUTES in
waf.py's init_waf): the dashboard should reflect traffic to the thing
being protected, not the admin polling their own dashboard.
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
TRAFFIC_FILE = os.path.join(LOG_DIR, "traffic_log.json")

# Keep the file bounded so a long-running demo doesn't grow it forever.
MAX_ENTRIES = 2000


def _ensure_file():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(TRAFFIC_FILE):
        with open(TRAFFIC_FILE, "w") as f:
            json.dump([], f)


def log_request(path, blocked, attack_type, source_ip):
    """Record one request to the public demo surface."""
    _ensure_file()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": path,
        "blocked": blocked,
        "attack_type": attack_type,  # None for clean requests
        "source_ip": source_ip,
    }

    with open(TRAFFIC_FILE, "r") as f:
        try:
            entries = json.load(f)
        except json.JSONDecodeError:
            entries = []

    entries.append(entry)
    entries = entries[-MAX_ENTRIES:]

    with open(TRAFFIC_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def get_traffic_log():
    _ensure_file()
    with open(TRAFFIC_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def get_traffic_stats():
    """
    Summarize the traffic log for the dashboard:
      - total requests inspected / blocked / block rate
      - a minute-bucketed timeline of allowed vs blocked requests
        (fine enough granularity that a single demo session - running
        test_attacks.sh, clicking around the forms - actually produces
        a readable shape instead of one flat bar)
    """
    entries = get_traffic_log()

    total = len(entries)
    blocked = sum(1 for e in entries if e["blocked"])
    allowed = total - blocked
    block_rate = blocked / total if total else 0.0

    buckets = defaultdict(lambda: {"allowed": 0, "blocked": 0})
    for e in entries:
        minute = e["timestamp"][:16]  # "YYYY-MM-DDTHH:MM"
        key = "blocked" if e["blocked"] else "allowed"
        buckets[minute][key] += 1

    timeline = [
        {"time": minute[11:], "allowed": counts["allowed"], "blocked": counts["blocked"]}
        for minute, counts in sorted(buckets.items())
    ]

    return {
        "total_requests": total,
        "total_blocked": blocked,
        "total_allowed": allowed,
        "block_rate": block_rate,
        "timeline": timeline,
    }
