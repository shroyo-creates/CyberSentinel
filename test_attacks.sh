#!/usr/bin/env bash
#
# test_attacks.sh - Sample attack requests to demonstrate the WAF.
#
# Make sure the Flask app is running first:
#     python app.py
#
# Then in another terminal, run:
#     ./test_attacks.sh
#
# Each malicious request below should be rejected with "HTTP/1.1 403"
# and a "Blocked by WAF" message. Afterwards, open
# http://localhost:5000/dashboard to see them all logged.

BASE_URL="http://localhost:5000"

echo "=================================================="
echo "0. Baseline: a CLEAN request (should pass, HTTP 200)"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$BASE_URL/search?q=hello"

echo
echo "=================================================="
echo "1. SQL Injection - classic tautology in login form"
echo "   Payload: admin' OR '1'='1"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "username=admin' OR '1'='1" \
    --data-urlencode "password=whatever"

echo
echo "=================================================="
echo "2. SQL Injection - UNION SELECT in search box"
echo "   Payload: 1' UNION SELECT username, password FROM users--"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -G "$BASE_URL/search" \
    --data-urlencode "q=1' UNION SELECT username, password FROM users--"

echo
echo "=================================================="
echo "3. XSS - <script> tag injected into search box"
echo "   Payload: <script>alert(1)</script>"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -G "$BASE_URL/search" \
    --data-urlencode "q=<script>alert(1)</script>"

echo
echo "=================================================="
echo "4. XSS - <img onerror=...> injected into login form"
echo "   Payload: <img src=x onerror=alert(1)>"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -X POST "$BASE_URL/login" \
    --data-urlencode "username=<img src=x onerror=alert(1)>" \
    --data-urlencode "password=whatever"

echo
echo "=================================================="
echo "5. Path Traversal - fetch /etc/passwd"
echo "   Payload: ../../../../etc/passwd"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -G "$BASE_URL/fetch" \
    --data-urlencode "file=../../../../etc/passwd"

echo
echo "=================================================="
echo "6. Path Traversal - URL-encoded traversal"
echo "   Payload: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
echo "=================================================="
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$BASE_URL/fetch?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

echo
echo "=================================================="
echo "Done. Open $BASE_URL/dashboard to see the blocked attempts."
echo "=================================================="
