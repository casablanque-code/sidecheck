#!/usr/bin/env python3
"""
Фикстура для проверки --json-body (0.2.0): реалистичный /login,
которому кроме пароля нужен ещё username, чтобы вообще дойти до
сравнения секрета — ровно тот случай, который --json-field без
--json-body не мог покрыть.

/vulnerable — сравнение вручную посимвольно, с усиленной задержкой
              (как в test-fixture/test_fixture.py) — сигнал искусственно
              увеличен, чтобы его было легко поймать через loopback.
/safe        — hmac.compare_digest, sidecheck не должен здесь ничего найти.

Неверный username -> всегда 401 без сравнения пароля (реалистичный ранний
выход) — если --json-body не передать, sidecheck будет слать только
{"password": "..."} без username и получит 401 на каждый запрос, то есть
не увидит вообще никакого сигнала (ни утечки, ни разницы между classes) —
это тоже полезно проверить как негативный кейс.

Запуск: python3 json_login_fixture.py
Логин: "admin", пароль: "correct-secret-key-123456"
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
            # ранний выход до сравнения пароля вообще — реалистично
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
