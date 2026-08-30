from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


vulnerable = os.environ.get("VULNERABLE") == "1"
created = False


class Handler(BaseHTTPRequestHandler):
    def reply(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.reply(200, {"ok": True})
        elif self.path == "/api/users/cvelab-canary" and created:
            self.reply(200, {"name": "cvelab-canary", "role": "admin"})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self) -> None:
        global created
        length = min(int(self.headers.get("Content-Length", "0")), 65536)
        self.rfile.read(length)
        if self.path == "/api/import" and vulnerable:
            created = True
            self.reply(201, {"created": True})
        else:
            self.reply(403, {"error": "forbidden"})

    def log_message(self, format: str, *args: object) -> None:
        return


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
