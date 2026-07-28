#!/usr/bin/env python3
"""
Control fixture for sidecheck.

/vulnerable — a manual, character-by-character comparison with an
              artificial delay per matched prefix byte (amplifies the
              signal so it's easy to catch even over loopback — in
              reality the leak is usually nanoseconds; here it's
              deliberately amplified to check that sidecheck can detect
              it at all).
/safe        — the same thing, but via hmac.compare_digest (real
              constant-time). sidecheck should find nothing here.

Run: python3 test_fixture.py
Then:  sidecheck check http://127.0.0.1:8000/vulnerable \
          --header X-API-Key --secret "correct-secret-key-123456" \
          --samples 3000

Safe endpoint as a control (should find nothing):
        sidecheck check http://127.0.0.1:8000/safe \
          --header X-API-Key --secret "correct-secret-key-123456" \
          --samples 3000

Secret: "correct-secret-key-123456"
"""

import hmac
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "correct-secret-key-123456"
DELAY_PER_MATCHED_BYTE = 0.0004  # 400us per matched byte — amplified signal for the demo


def vulnerable_compare(candidate: str) -> bool:
    for i, ch in enumerate(candidate):
        if i >= len(SECRET) or ch != SECRET[i]:
            return False
        time.sleep(DELAY_PER_MATCHED_BYTE)  # artificial leak
    return len(candidate) == len(SECRET)


def safe_compare(candidate: str) -> bool:
    return hmac.compare_digest(candidate.encode(), SECRET.encode())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet server, don't clutter the output

    def do_GET(self):
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
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("test fixture running on http://127.0.0.1:8000")
    print("  /vulnerable — should be flagged by sidecheck")
    print("  /safe       — should NOT be flagged")
    print(f"  real secret: {SECRET!r} (for constructing --value-b)")
    server.serve_forever()
