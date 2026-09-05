#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
INSTALL_ROOT="${CVELAB_INSTALL_ROOT:-$HOME/.local/share/cvelab}"
VENV="$INSTALL_ROOT/venv"
BIN_DIR="${CVELAB_BIN_DIR:-$HOME/.local/bin}"
LINK="$BIN_DIR/cvelab"

fail() {
  printf 'cvelab install: %s\n' "$*" >&2
  exit 1
}

command -v "$PYTHON" >/dev/null 2>&1 || fail "python3 was not found"
command -v git >/dev/null 2>&1 || fail "git was not found"
command -v docker >/dev/null 2>&1 || fail "docker was not found"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum was not found"

"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required"
docker compose version >/dev/null 2>&1 \
  || fail "the Docker Compose plugin is not available"
docker info >/dev/null 2>&1 \
  || fail "Docker Engine is not running or the current user cannot access it"

shopt -s nullglob
wheels=("$SCRIPT_DIR"/wheels/cvelab-*.whl)
(( ${#wheels[@]} == 1 )) || fail "expected exactly one cvelab wheel in $SCRIPT_DIR/wheels"
(
  cd "$SCRIPT_DIR"
  sha256sum --check SHA256SUMS
) || fail "wheel checksum verification failed"

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
"$PYTHON" -m venv "$VENV"
"$VENV/bin/python" -m pip install --no-deps --force-reinstall "${wheels[0]}"

if [[ -e "$LINK" && ! -L "$LINK" ]]; then
  fail "$LINK exists and is not a symbolic link"
fi
ln -sfn "$VENV/bin/cvelab" "$LINK"

printf 'cvelab installed at %s\n' "$VENV/bin/cvelab"
printf 'launcher: %s\n' "$LINK"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) printf 'add this to your shell profile: export PATH="%s:$PATH"\n' "$BIN_DIR" ;;
esac
