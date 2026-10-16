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

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import __version__, progress, upload, usage
from .ai import resolve_provider
from .autoflow import run_auto_workflow
from .closed import run_closed_lab
from .closed_auto import run_closed_auto
from .core import (
    build_lab,
    redact,
    register_environment_secrets,
    register_secret,
    run_lab,
)
from .deliverables import create_deliverables
from .doctor import doctor_command
from .providers import SELECTABLE
from .providers import get as get_provider
from .sourcegen import generate_source_lab


def add_ai_credentials(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--provider",
        choices=SELECTABLE,
        default="auto",
        help="AI provider (default: infer from environment, otherwise OpenAI)",
    )
    command.add_argument(
        "--key",
        nargs="?",
        const="__PROMPT__",
        help="Provider API key; omit the value to enter it securely (optional for local)",
    )
    command.add_argument("--model", help="Provider model ID (or use CVELAB_MODEL)")
    command.add_argument(
        "--base-url",
        help="Local OpenAI-compatible base URL (default: http://127.0.0.1:11434/v1)",
    )


def add_upload_flags(command: argparse.ArgumentParser) -> None:
    """Uploading needs a token; these only say what to do when one exists."""
    command.add_argument(
        "--no-upload",
        action="store_true",
        help=f"Never send the report, even when {upload.TOKEN_VARIABLE} is set",
    )
    command.add_argument(
        "--upload-poc",
        action="store_true",
        help="Include the exploit and plan in the upload (off by default)",
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="cvelab",
        description="Generate isolated, source-backed CVE reproduction labs.",
    )
    root.add_argument(
        "--version",
        action="version",
        version=f"cvelab {__version__}",
        help="Show the installed version and exit",
    )
    root.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress on stderr (or set CVELAB_QUIET)",
    )
    root.add_argument(
        "--output-root",
        type=Path,
        default=Path.cwd() / "generated-labs",
        help="Directory for generated labs (default: ./generated-labs)",
    )
    sub = root.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Collect metadata and generate a lab")
    build.add_argument("cve")
    build.add_argument("--cwe", help="Override CWE when public metadata is incomplete")
    build.add_argument("--ai", choices=("off", "auto", "on"), default="auto")
    add_ai_credentials(build)

    source = sub.add_parser("source", help="Generate from vulnerable source, with a fixed revision when public")
    source.add_argument("cve")
    source.add_argument("--repo", help="Public GitHub or GitLab HTTPS repository")
    source.add_argument("--fixed-ref", help="Commit containing the security fix")
    source.add_argument("--vulnerable-ref", help="Vulnerable commit (default: parent of fixed commit)")
    add_ai_credentials(source)

    source_all = sub.add_parser(
        "source-all",
        help="Generate from source and validate vulnerable versus patched end-to-end",
    )
    source_all.add_argument("cve")
    source_all.add_argument("--repo", help="Public GitHub or GitLab HTTPS repository")
    source_all.add_argument("--fixed-ref", help="Commit containing the security fix")
    source_all.add_argument("--vulnerable-ref", help="Vulnerable commit (default: parent of fixed commit)")
    source_all.add_argument("--keep", action="store_true", help="Keep containers running")
    add_ai_credentials(source_all)
    add_upload_flags(source_all)

    auto = sub.add_parser(
        "auto",
        help="Choose the best lab strategy, validate it, and emit PoC, walkthrough, and report",
    )
    auto.add_argument("cve")
    auto.add_argument("--repo", help="Optional public GitHub or GitLab HTTPS repository override")
    auto.add_argument("--fixed-ref", help="Optional commit containing the security fix")
    auto.add_argument("--vulnerable-ref", help="Optional vulnerable commit")
    auto.add_argument(
        "--ai",
        choices=("on",),
        default="on",
        help="AI generation is always enabled for the automatic workflow",
    )
    auto.add_argument("--keep", action="store_true", help="Keep containers running")
    auto.add_argument(
        "--max-attempts",
        type=int,
        default=4,
        help="Maximum automatic E2E validation attempts (default: 4)",
    )
    add_ai_credentials(auto)
    add_upload_flags(auto)

    doctor = sub.add_parser(
        "doctor",
        help="Check the environment before spending time and money on a run",
    )
    doctor.add_argument(
        "--offline",
        action="store_true",
        help="Skip the provider reachability check",
    )
    doctor.add_argument("--json", action="store_true", help="Emit the report as JSON")
    add_ai_credentials(doctor)

    upload_cmd = sub.add_parser(
        "upload",
        help="Send an already-generated lab's report to the control plane",
    )
    upload_cmd.add_argument("cve")
    upload_cmd.add_argument(
        "--upload-poc",
        action="store_true",
        help="Include the exploit and plan in the upload (off by default)",
    )
    upload_cmd.add_argument(
        "--provider", choices=SELECTABLE, help="Provider that produced this lab"
    )
    upload_cmd.add_argument("--model", help="Model that produced this lab")
    upload_cmd.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be sent and send nothing",
    )

    run = sub.add_parser("run", help="Build containers and validate the available source variants")
    run.add_argument("cve")
    run.add_argument("--keep", action="store_true", help="Keep containers running")
    add_upload_flags(run)

    closed = sub.add_parser(
        "closed",
        help="Validate a user-supplied closed software Docker image through loopback HTTP",
    )
    closed.add_argument("cve")
    closed.add_argument("--vulnerable-image", required=True, help="User-supplied vulnerable image")
    closed.add_argument("--fixed-image", help="Optional user-supplied fixed image")
    closed.add_argument("--container-port", required=True, type=int, help="HTTP port inside the image")
    closed.add_argument("--health-path", default="/", help="Relative readiness path")
    closed.add_argument("--contract", required=True, type=Path, help="Inspectable HTTP attack contract JSON")

    closed_auto = sub.add_parser(
        "closed-auto",
        help="Resolve and validate a closed software HTTP PoC from only a CVE identifier",
    )
    closed_auto.add_argument("cve")
    add_ai_credentials(closed_auto)

    all_cmd = sub.add_parser("all", help="Generate and validate a lab")
    all_cmd.add_argument("cve")
    all_cmd.add_argument("--cwe", help="Override CWE when public metadata is incomplete")
    all_cmd.add_argument("--ai", choices=("off", "auto", "on"), default="auto")
    add_ai_credentials(all_cmd)
    all_cmd.add_argument("--keep", action="store_true", help="Keep containers running")
    return root


def upload_command(
    cve: str,
    output_root: Path,
    include_poc: bool,
    dry_run: bool,
    provider: str | None = None,
    model: str | None = None,
) -> int:
    """Send a lab that is already on disk."""
    lab_dir = output_root.resolve() / cve.upper()
    if not (lab_dir / "artifacts").is_dir():
        print(
            json.dumps({"ok": False, "error": f"No generated lab at {lab_dir}"}, indent=2),
            file=sys.stderr,
        )
        return 1
    # The run has finished, so its outcome is whatever report.json recorded.
    try:
        report = json.loads((lab_dir / "artifacts" / "report.json").read_text("utf-8"))
    except (OSError, ValueError):
        report = {}
    result = {
        "ok": bool(report.get("proof_checks")),
        "cve": cve.upper(),
        "status": report.get("status") or ("VALIDATED" if report.get("proof_checks") else None),
        "automation": report.get("automation", {}),
    }
    payload = upload.collect(
        lab_dir, result, provider=provider, model=model, include_poc=include_poc
    )
    if dry_run:
        print(upload.describe(payload))
        return 0
    token = upload.find_token()
    if not token:
        print(
            f"No upload token. Create one at {upload.endpoint()}/app/ and set "
            f"{upload.TOKEN_VARIABLE}, or write it to {upload.TOKEN_FILE}.",
            file=sys.stderr,
        )
        return 1
    progress.step(upload.describe(payload))
    try:
        answer = upload.send(payload, token)
    except upload.UploadError as error:
        print(json.dumps({"ok": False, "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(answer, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.quiet:
        progress.silence()
    register_environment_secrets()
    try:
        api_key = getattr(args, "key", None)
        if api_key == "__PROMPT__":
            selected_provider = resolve_provider(getattr(args, "provider", None))
            provider_label = get_provider(selected_provider).label
            api_key = getpass.getpass(f"{provider_label} API key: ")
        register_secret(api_key)
        model = getattr(args, "model", None)
        provider = getattr(args, "provider", None)
        base_url = getattr(args, "base_url", None)
        if args.command == "upload":
            return upload_command(
                args.cve, args.output_root, args.upload_poc, args.dry_run,
                args.provider, args.model,
            )
        if args.command == "doctor":
            return doctor_command(
                args.output_root, provider, model, api_key, base_url,
                args.offline, args.json,
            )
        if args.command == "build":
            result = build_lab(
                args.cve, args.output_root, args.cwe, args.ai,
                api_key, model, provider, base_url,
            )
        elif args.command == "auto":
            result = run_auto_workflow(
                args.cve,
                args.output_root,
                args.repo,
                args.fixed_ref,
                args.vulnerable_ref,
                api_key,
                model,
                args.keep,
                args.max_attempts,
                provider=provider,
                base_url=base_url,
            )
        elif args.command in {"source", "source-all"}:
            generated = generate_source_lab(
                args.cve,
                args.output_root,
                args.repo,
                args.fixed_ref,
                args.vulnerable_ref,
                api_key,
                model,
                provider,
                base_url,
            )
            if args.command == "source-all" and generated.get("ok"):
                result = run_lab(args.cve, args.output_root, args.keep)
            else:
                result = generated
        elif args.command == "closed-auto":
            result = run_closed_auto(
                args.cve, args.output_root, api_key, model, provider, base_url
            )
        elif args.command == "closed":
            result = run_closed_lab(
                args.cve,
                args.output_root,
                args.vulnerable_image,
                args.fixed_image,
                args.container_port,
                args.health_path,
                args.contract,
            )
        elif args.command == "run":
            validated = run_lab(args.cve, args.output_root, args.keep)
            result = create_deliverables(
                args.cve.upper(), args.output_root.resolve() / args.cve.upper(), validated
            )
        else:
            build_lab(
                args.cve, args.output_root, args.cwe, args.ai,
                api_key, model, provider, base_url,
            )
            result = run_lab(args.cve, args.output_root, args.keep)
        print(redact(json.dumps(result, indent=2)))
        summary = usage.format_summary()
        if summary:
            progress.step(summary)
        # After the result is printed: the lab is the deliverable and must be
        # reported even if the control plane is unreachable.
        if not getattr(args, "no_upload", True):
            cve = str(result.get("cve") or args.cve).upper()
            upload.upload_result(
                args.output_root.resolve() / cve,
                result,
                provider=provider,
                model=model,
                include_poc=args.upload_poc,
            )
        return 0 if result.get("ok", True) else 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(
            redact(json.dumps({"ok": False, "error": str(exc)}, indent=2)),
            file=sys.stderr,
        )
        return 1
