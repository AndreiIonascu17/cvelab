#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/dist-linux}"
PYTHON="${PYTHON:-python3}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cvelab-linux-build.XXXXXXXX")"
VENV="$STAGE/venv"

cleanup() {
  if [[ -n "${STAGE:-}" && -d "$STAGE" ]]; then
    rm -rf -- "$STAGE"
  fi
}
trap cleanup EXIT

command -v "$PYTHON" >/dev/null 2>&1 || {
  printf 'build-linux: python3 was not found\n' >&2
  exit 1
}

"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  printf 'build-linux: Python 3.11 or newer is required\n' >&2
  exit 1
}

"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip wheel --no-deps --wheel-dir "$STAGE/wheels" "$ROOT"

VERSION="$("$VENV/bin/python" -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("'"$ROOT"'/pyproject.toml").read_text())["project"]["version"])')"
BUNDLE_NAME="cvelab-$VERSION-linux"
BUNDLE="$STAGE/$BUNDLE_NAME"

mkdir -p "$BUNDLE/wheels" "$OUTPUT"
cp "$ROOT/linux/install.sh" "$BUNDLE/install.sh"
cp "$ROOT/linux/README.md" "$BUNDLE/README.md"
cp "$STAGE"/wheels/cvelab-*.whl "$BUNDLE/wheels/"
chmod 0755 "$BUNDLE/install.sh"

(
  cd "$BUNDLE"
  sha256sum wheels/*.whl > SHA256SUMS
)

tar -C "$STAGE" -czf "$OUTPUT/$BUNDLE_NAME.tar.gz" "$BUNDLE_NAME"
(
  cd "$OUTPUT"
  sha256sum "$BUNDLE_NAME.tar.gz" > "$BUNDLE_NAME.tar.gz.sha256"
)

printf 'Linux bundle: %s\n' "$OUTPUT/$BUNDLE_NAME.tar.gz"
printf 'Checksum: %s\n' "$OUTPUT/$BUNDLE_NAME.tar.gz.sha256"
