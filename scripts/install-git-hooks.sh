#!/usr/bin/env bash
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

# Installs the local pre-commit hook. GitHub secret scanning with push
# protection is not available on a private repository without a Code Security
# licence, so the same job is done here, before the commit exists.

set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel)"
HOOK="$ROOT/.git/hooks/pre-commit"

if [[ -e "$HOOK" && ! -L "$HOOK" ]] && ! grep -q 'cvelab secret scan' "$HOOK"; then
  printf 'A pre-commit hook already exists and was not written by CVELab:\n  %s\n' "$HOOK" >&2
  printf 'Merge it manually, or move it aside and re-run this script.\n' >&2
  exit 1
fi

cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# cvelab secret scan — installed by scripts/install-git-hooks.sh
set -Eeuo pipefail

# Realistic key shapes only. Placeholders such as OPENAI_API_KEY=YOUR_KEY must
# not trip the hook, or the hook gets disabled and protects nothing.
PATTERNS=(
  'sk-ant-[A-Za-z0-9_-]{24,}'
  'sk-proj-[A-Za-z0-9_-]{24,}'
  'sk-[A-Za-z0-9]{32,}'
  'AKIA[0-9A-Z]{16}'
  'gh[pousr]_[A-Za-z0-9]{36,}'
  'AIza[0-9A-Za-z_-]{35}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
)

staged="$(git diff --cached --name-only --diff-filter=ACM)"
[[ -z "$staged" ]] && exit 0

found=0
while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  # Only the added lines, so pre-existing content is not re-reported.
  added="$(git diff --cached -U0 -- "$file" | grep '^+' | grep -v '^+++' || true)"
  # Test fixtures and documentation need values shaped like credentials.
  # An explicit marker is auditable; a looser pattern would not be.
  added="$(printf '%s' "$added" | grep -v 'pragma: allowlist secret' || true)"
  [[ -z "$added" ]] && continue
  for pattern in "${PATTERNS[@]}"; do
    if match="$(printf '%s' "$added" | grep -oE -- "$pattern" | head -1)"; then
      if [[ -n "$match" ]]; then
        printf 'Possible secret in %s: %s...\n' "$file" "${match:0:12}" >&2
        found=1
      fi
    fi
  done
done <<< "$staged"

if (( found )); then
  cat >&2 <<'MSG'

Commit blocked. Remove the credential, then rotate it — a key that reached a
working tree should be considered exposed.

If this is a false positive:
    git commit --no-verify

MSG
  exit 1
fi
exit 0
HOOKEOF

chmod +x "$HOOK"
printf 'pre-commit hook installed: %s\n' "$HOOK"
