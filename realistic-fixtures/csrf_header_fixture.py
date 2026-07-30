#!/usr/bin/env python3
"""
Fixture for exercising --extra-header: a realistic endpoint gated by a
CSRF token header, on top of the value actually under test — the header
equivalent of what json_login_fixture.py covers for JSON bodies.

Without the correct X-CSRF-Token, every request gets 403 before the
X-API-Key comparison is even reached, regardless of whether the key is
right or wrong — sidecheck will (correctly, if misleadingly) report no
signal at all unless --extra-header supplies the token.

Run: python3 csrf_header_fixture.py
CSRF token: "expected-csrf-token", API key: "correct-secret-key-123456"
"""

import hmac
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CSRF_TOKEN = "expected-csrf-token"
SECRET = "correct-secret-key-123456"
DELAY_PER_MATCHED_BYTE = 0.0004


def vulnerable_compare(candidate: str) -> bool:
    for i, ch in enumerate(candidate):
        if i >= len(SECRET) or ch != SECRET[i]:
            return False
        time.sleep(DELAY_PER_MATCHED_BYTE)
    return len(candidate) == len(SECRET)


def safe_compare(candidate: str) -> bool:
    return hmac.compare_digest(candidate.encode(), SECRET.encode())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("X-CSRF-Token") != CSRF_TOKEN:
            # early exit before comparing the API key at all — realistic
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return

        candidate = self.headers.get("X-API-Key", "")

        if self.path == "/vulnerable":
            ok = vulnerable_compare(candidate)
        elif self.path == "/safe":
            ok = safe_compare(candidate)
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok" if ok else b"denied")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8004), Handler)
    print("csrf header fixture running on http://0.0.0.0:8004 (reachable on any interface, not just loopback)")
    print("  /vulnerable — should be flagged by sidecheck (with --extra-header)")
    print("  /safe       — should NOT be flagged")
    print(f"  csrf token: {CSRF_TOKEN!r}, api key: {SECRET!r}")
    server.serve_forever()
