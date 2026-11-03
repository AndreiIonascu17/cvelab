"""A note store that forgets to check who is asking. Stands in for a product."""
import json, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A slow boot on purpose: the validator has to wait for the healthcheck, which
# is what depends_on is for and what a regression here would skip.
time.sleep(5)
NOTES = {"1": {"owner": "alice", "body": "cvelab-e2e-secret"}}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            return self.answer(200, {"ok": True})
        if self.path.startswith("/notes/"):
            note = NOTES.get(self.path.rsplit("/", 1)[-1])
            # Fixed: a note is served only to its owner, named in Authorization.
            owner = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            if note and owner == note["owner"]:
                return self.answer(200, note)
            return self.answer(403 if note else 404, {})
        self.answer(404, {})

    def answer(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
