# CVELab for Linux

This bundle installs CVELab natively on Linux. Docker Desktop and WSL are not required.

## Requirements

- A Linux distribution supported by Python and Docker Engine.
- Python 3.11 or newer, with the `venv` module.
- Git.
- A running Docker Engine.
- The Docker Compose plugin.
- Access to the Docker socket for the current user.

## Installation

Extract the archive and run:

```bash
tar -xzf cvelab-*-linux.tar.gz
cd cvelab-*-linux
./install.sh
```

If `~/.local/bin` is not in `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

```bash
cvelab --output-root "$HOME/cvelab-labs" \
  auto CVE-YYYY-NNNNN \
  --ai on \
  --key \
  --model gpt-5.6-sol
```

At the `OpenAI API key:` prompt, enter only the API key. The installer does not save the key.

## CVEs without a public fix

If the repository and vulnerable revision are verifiable but no exact public fix is available, CVELab can generate `VULNERABLE_ONLY_REPRODUCTION`. The report must indicate:

```json
{
  "real_poc_verified": true,
  "fix_status": "PUBLIC_FIX_NOT_IDENTIFIED",
  "patched_tested": false,
  "differential_confirmed": false
}
```

## Uninstallation

The installer does not modify system packages. To uninstall, remove the virtual environment and symbolic link created at:

```text
~/.local/share/cvelab/venv
~/.local/bin/cvelab
```

Data in lab directories is not deleted automatically.

For configuration, usage, result interpretation, and troubleshooting, see
`GUIDE.md` in the repository.
