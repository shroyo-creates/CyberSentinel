# PatternShield

A simplified Web Application Firewall (WAF) that inspects incoming HTTP requests for common attack patterns before they reach the application — built as a hands-on exploration of OWASP Top 10 vulnerabilities.

## What it does

Unlike a traditional firewall that filters by IP/port, PatternShield inspects request *content* — form fields, query parameters, and URL paths — and blocks requests matching known malicious patterns.

## Detected Attack Types

- **SQL Injection (SQLi)** — `' OR 1=1`, `UNION SELECT`, `--`, `DROP TABLE`
- **Cross-Site Scripting (XSS)** — `<script>`, `onerror=`, `javascript:`
- **Path Traversal** — `../`, `..\`, encoded variants like `%2e%2e%2f`

## Features

- Middleware-based request interception (runs before requests hit the app)
- Regex-based pattern matching for each attack category
- Blocks malicious requests with a 403 response
- Logs every blocked attempt (timestamp, attack type, payload, source)
- Dashboard to visualize caught attacks and attack-type breakdown

## Tech Stack

- Python, Flask
- JSON-based logging (no external DB required)
- HTML/CSS dashboard

## Why

This project maps directly to real-world OWASP Top 10 vulnerability classes, built to understand how WAFs work at a fundamental, pattern-matching level.
