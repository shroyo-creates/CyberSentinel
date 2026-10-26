# Dashboard frontend (React + Vite)

This React app powers **only** `/dashboard` — everything else in
CyberSentinel (`/login`, `/search`, `/fetch`, `/admin/*`) is still plain
Flask + Jinja templates, on purpose: it keeps the "request gets blocked
with a 403" behaviour dead simple to demo without a frontend build step
in the way.

It talks to Flask over two JSON endpoints:

- `GET /api/dashboard` — the attack log, summary counts, per-day
  timeline, top source IPs, and the latest `evaluate_waf.py` benchmark.
  Polled every 5 seconds for a "live" feel.
- `POST /api/admin/settings` — flips the WAF on/off or the login query
  mode (`{"action": "toggle_waf"}` / `{"action": "toggle_query_mode"}`).

Both require the admin session cookie set by `/admin/login` (Flask-side,
not part of this app) and respond `401` if you're not logged in, which
the app turns into a redirect to `/admin/login`.

## Building for use with Flask (what you normally want)

```bash
cd frontend
npm install
npm run build
```

This outputs `app.js` and `app.css` into `../static/dashboard/` with
**fixed filenames** (no content hash) so `templates/dashboard.html` can
reference them directly. After building, just run the Flask app as
usual (`python app.py` from the project root) and visit `/dashboard`.

The built output is committed to the repo, so you don't *have* to run
this yourself just to use the app — only when you change the React code.

## Developing with hot reload

```bash
# terminal 1, from the project root
python app.py

# terminal 2
cd frontend
npm run dev
```

Log in as admin at `http://localhost:5000/admin/login` first (so the
session cookie exists), then open `http://localhost:5173` — Vite's dev
server proxies `/api/*` requests to Flask on port 5000 (see
`vite.config.js`), so the React app talks to the real backend while you
get instant hot-reload on save.
