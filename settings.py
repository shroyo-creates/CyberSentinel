"""
settings.py - admin-controlled demo toggles.

These are plain in-memory globals (not a database) and reset to safe
defaults every time the app restarts. They exist purely so the admin
can demonstrate, live, why BOTH layers of defense matter:

  waf_enabled : bool
      When True (default), waf.py blocks malicious requests before the
      /login route ever runs. When an admin turns this off (from
      /admin/settings), malicious input reaches the route handler.

  query_mode : "safe" | "vulnerable"
      Controls how database.py builds the SQL query for /login.
      "safe" uses parameterized queries (the correct way). "vulnerable"
      builds the query with raw string formatting (the classic SQLi bug).

Demo talking point: with the WAF off AND query_mode="vulnerable", a
login bypass payload actually logs you in. Switch query_mode to "safe"
(WAF still off) and the same payload fails - because parameterized
queries treat user input as data, never as part of the SQL statement.
Turn the WAF back on and the payload never reaches the database at all.
"""

waf_enabled = True
query_mode = "safe"
