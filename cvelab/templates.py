from __future__ import annotations

APP_PY = r'''import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CWE = os.environ.get("CWE_CLASS", "CWE-434").upper()
MODE = os.environ.get("LAB_MODE", "patched")
ROLE = os.environ.get("LAB_ROLE", "target")
MARKER = os.environ.get("LAB_MARKER", "CVELAB-MARKER")
SCENARIO = os.environ.get("LAB_SCENARIO", "default")
UPLOADS = {}
PUBLIC = Path("/app/public")
PUBLIC.mkdir(parents=True, exist_ok=True)
Path("/tmp/cvelab-secret.txt").write_text(MARKER, encoding="utf-8")


def send(handler, status, body, content_type="application/json"):
    if not isinstance(body, bytes):
        body = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def json_body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    return json.loads(handler.rfile.read(length) or b"{}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/health":
            return send(self, 200, '{"ok":true}')
        if ROLE == "metadata" and parsed.path == "/marker":
            return send(self, 200, MARKER, "text/plain")

        if CWE == "CWE-284" and SCENARIO == "namespace_injection" and parsed.path.startswith("/objects/"):
            namespace = parsed.path.rsplit("/", 1)[-1]
            content = UPLOADS.get("namespace:" + namespace)
            if content is None:
                return send(self, 404, "not found", "text/plain")
            return send(self, 200, content, "text/plain")

        if CWE == "CWE-284" and SCENARIO != "namespace_injection" and parsed.path == "/admin":
            if MODE == "patched" and self.headers.get("X-Role", "guest") != "admin":
                return send(self, 403, '{"error":"access denied"}')
            return send(self, 200, MARKER, "text/plain")

        if CWE == "CWE-434" and parsed.path.startswith("/uploads/"):
            name = parsed.path.rsplit("/", 1)[-1]
            if name in UPLOADS:
                return send(self, 200, UPLOADS[name], "text/plain")
            return send(self, 404, "not found", "text/plain")

        if CWE == "CWE-918" and parsed.path == "/fetch":
            target = query.get("url", [""])[0]
            host = urllib.parse.urlparse(target).hostname or ""
            if MODE == "patched" and host not in {"example.com", "www.example.com"}:
                return send(self, 400, '{"error":"destination blocked"}')
            try:
                with urllib.request.urlopen(target, timeout=3) as response:
                    data = response.read(4096)
                return send(self, 200, data, "text/plain")
            except Exception as exc:
                return send(self, 502, json.dumps({"error": str(exc)}))

        if CWE == "CWE-22" and parsed.path == "/download":
            supplied = query.get("path", [""])[0]
            candidate = (PUBLIC / supplied).resolve()
            if MODE == "patched":
                try:
                    candidate.relative_to(PUBLIC.resolve())
                except ValueError:
                    return send(self, 400, '{"error":"path blocked"}')
            try:
                return send(self, 200, candidate.read_bytes(), "text/plain")
            except OSError:
                return send(self, 404, "not found", "text/plain")

        if CWE == "CWE-78" and parsed.path == "/run":
            value = query.get("value", [""])[0]
            if MODE == "patched" and not re.fullmatch(r"[0-9]+", value):
                return send(self, 400, '{"error":"value blocked"}')
            command = "printf '%s' " + value
            completed = subprocess.run(
                command if MODE == "vulnerable" else ["printf", "%s", value],
                shell=MODE == "vulnerable",
                capture_output=True,
                text=True,
                timeout=2,
            )
            return send(self, 200, completed.stdout, "text/plain")

        if CWE == "CWE-89" and parsed.path == "/search":
            username = query.get("username", [""])[0]
            db = sqlite3.connect(":memory:")
            db.execute("CREATE TABLE users (username TEXT, secret TEXT)")
            db.execute("INSERT INTO users VALUES (?, ?)", ("admin", MARKER))
            db.execute("INSERT INTO users VALUES (?, ?)", ("guest", "public"))
            try:
                if MODE == "vulnerable":
                    rows = db.execute(
                        "SELECT username, secret FROM users WHERE username = '" + username + "'"
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT username, secret FROM users WHERE username = ?", (username,)
                    ).fetchall()
                return send(self, 200, json.dumps({"rows": rows}))
            except sqlite3.Error as exc:
                return send(self, 400, json.dumps({"error": str(exc)}))
            finally:
                db.close()

        return send(self, 404, "not found", "text/plain")

    def do_POST(self):
        if CWE == "CWE-284" and SCENARIO == "namespace_injection" and self.path == "/inject":
            body = json_body(self)
            source = str(body.get("source_namespace", ""))
            destination = str(body.get("destination_namespace", ""))
            content = str(body.get("content", ""))
            if not source or not destination:
                return send(self, 400, '{"error":"namespaces required"}')
            if MODE == "patched" and destination != source:
                return send(self, 403, '{"error":"cross-namespace injection blocked"}')
            UPLOADS["namespace:" + destination] = content
            return send(self, 201, json.dumps({"created_in": destination}))
        if CWE != "CWE-434" or self.path != "/upload":
            return send(self, 404, "not found", "text/plain")
        body = json_body(self)
        filename = Path(str(body.get("filename", ""))).name
        content = str(body.get("content", ""))
        if not filename:
            return send(self, 400, '{"error":"filename required"}')
        if MODE == "patched" and Path(filename).suffix.lower() not in {".txt", ".md"}:
            return send(self, 400, '{"error":"file type blocked"}')
        UPLOADS[filename] = content
        return send(self, 201, json.dumps({"url": "/uploads/" + filename}))


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

VALIDATOR_PY = r'''import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

plan = json.loads(open("plan.json", encoding="utf-8").read())
marker = plan["marker"]
cwe = plan["cwe"]
scenario = plan.get("scenario", "default")


def request_once(base):
    try:
        if cwe == "CWE-434":
            filename = "cvelab-marker.php"
            body = json.dumps({"filename": filename, "content": marker}).encode()
            req = urllib.request.Request(
                base + "/upload", data=body,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                uploaded = json.load(response)
            with urllib.request.urlopen(base + uploaded["url"], timeout=5) as response:
                content = response.read().decode()
            return {"confirmed": marker in content, "evidence": content}
        if cwe == "CWE-284" and scenario == "namespace_injection":
            body = json.dumps({
                "source_namespace": "tenant-a",
                "destination_namespace": "kube-system",
                "content": marker,
            }).encode()
            req = urllib.request.Request(
                base + "/inject", data=body,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
            url = base + "/objects/kube-system"
        elif cwe == "CWE-284":
            url = base + "/admin"
        elif cwe == "CWE-918":
            url = base + "/fetch?" + urllib.parse.urlencode(
                {"url": "http://metadata:8080/marker"}
            )
        elif cwe == "CWE-22":
            url = base + "/download?" + urllib.parse.urlencode(
                {"path": "../../tmp/cvelab-secret.txt"}
            )
        elif cwe == "CWE-78":
            url = base + "/run?" + urllib.parse.urlencode(
                {"value": "safe; printf " + marker}
            )
        elif cwe == "CWE-89":
            url = base + "/search?" + urllib.parse.urlencode(
                {"username": "x' OR '1'='1' --"}
            )
        else:
            return {"confirmed": False, "evidence": "unsupported CWE"}
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read().decode()
        return {"confirmed": marker in content, "evidence": content[:500]}
    except urllib.error.HTTPError as exc:
        return {"confirmed": False, "evidence": "HTTP " + str(exc.code)}
    except Exception as exc:
        return {"confirmed": False, "evidence": type(exc).__name__ + ": " + str(exc)}


def request(base):
    result = None
    for _ in range(20):
        result = request_once(base)
        if not result["evidence"].startswith(("URLError:", "ConnectionRefusedError:")):
            return result
        time.sleep(1)
    return result


results = {
    "vulnerable": request(os.getenv("CVELAB_VULNERABLE_URL", "http://127.0.0.1:" + str(plan["ports"]["vulnerable"]))),
    "patched": request(os.getenv("CVELAB_PATCHED_URL", "http://127.0.0.1:" + str(plan["ports"]["patched"]))),
}
results["differential_confirmed"] = (
    results["vulnerable"]["confirmed"] and not results["patched"]["confirmed"]
)
print(json.dumps(results, indent=2))
sys.exit(0 if results["differential_confirmed"] else 2)
'''

DOCKERFILE = '''FROM python:3.13-alpine
WORKDIR /app
COPY app.py /app/app.py
RUN addgroup -S lab && adduser -S lab -G lab && mkdir -p /app/public && chown -R lab:lab /app
USER lab
EXPOSE 8080
CMD ["python", "/app/app.py"]
'''

VALIDATOR_DOCKERFILE = '''FROM python:3.13-alpine
WORKDIR /validator
COPY validator.py plan.json /validator/
RUN addgroup -S validator && adduser -S validator -G validator && chown -R validator:validator /validator
USER validator
CMD ["python", "/validator/validator.py"]
'''


def compose_yaml(cwe: str, marker: str, vulnerable_port: int, patched_port: int, scenario: str = "default") -> str:
    return f'''services:
  vulnerable:
    build: ./app
    environment:
      CWE_CLASS: "{cwe}"
      LAB_MODE: vulnerable
      LAB_MARKER: "{marker}"
      LAB_SCENARIO: "{scenario}"
    networks: [labnet]
    mem_limit: 128m
    cpus: 0.50
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 2s
      timeout: 2s
      retries: 20
  patched:
    build: ./app
    environment:
      CWE_CLASS: "{cwe}"
      LAB_MODE: patched
      LAB_MARKER: "{marker}"
      LAB_SCENARIO: "{scenario}"
    networks: [labnet]
    mem_limit: 128m
    cpus: 0.50
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 2s
      timeout: 2s
      retries: 20
  metadata:
    build: ./app
    environment:
      CWE_CLASS: "{cwe}"
      LAB_ROLE: metadata
      LAB_MARKER: "{marker}"
      LAB_SCENARIO: "{scenario}"
    networks: [labnet]
    mem_limit: 64m
    cpus: 0.25
    security_opt: ["no-new-privileges:true"]
  validator:
    profiles: ["tools"]
    build: ./validator
    environment:
      CVELAB_VULNERABLE_URL: "http://vulnerable:8080"
      CVELAB_PATCHED_URL: "http://patched:8080"
    depends_on:
      vulnerable:
        condition: service_healthy
      patched:
        condition: service_healthy
      metadata:
        condition: service_started
    networks: [labnet]
    mem_limit: 64m
    cpus: 0.25
    security_opt: ["no-new-privileges:true"]
networks:
  labnet:
    internal: true
'''
