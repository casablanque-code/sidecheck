#!/usr/bin/env python3
"""
Fixture for exercising --json-body (0.2.0): a realistic /login that
needs a username besides the password to even reach the secret
comparison — exactly the case --json-field without --json-body
couldn't cover.

/vulnerable — a manual character-by-character comparison, with an
              amplified delay (like test-fixture/test_fixture.py) —
              the signal is artificially amplified so it's easy to
              catch over loopback.
/safe        — hmac.compare_digest, sidecheck should find nothing here.

Wrong username -> always 401 without comparing the password (a
realistic early exit) — if --json-body isn't passed, sidecheck will
only send {"password": "..."} with no username and get a 401 on
every request, i.e. it won't see any signal at all (neither a leak
nor a difference between classes) — useful to check as a negative
case too.

Run: python3 json_login_fixture.py
Login: "admin", password: "correct-secret-key-123456"
"""

import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERNAME = "admin"
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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}

        username = body.get("username", "")
        password = body.get("password", "")

        if username != USERNAME:
            # early exit before comparing the password at all — realistic
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"denied")
            return

        if self.path == "/vulnerable":
            ok = vulnerable_compare(password)
        elif self.path == "/safe":
            ok = safe_compare(password)
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok" if ok else b"denied")


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8003), Handler)
    print("json login fixture running on http://127.0.0.1:8003")
    print("  /vulnerable — should be flagged by sidecheck (with --json-body)")
    print("  /safe       — should NOT be flagged")
    print(f"  username: {USERNAME!r}, password: {SECRET!r}")
    server.serve_forever()
