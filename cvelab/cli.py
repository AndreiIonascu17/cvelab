from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .core import build_lab, run_lab
from .closed import run_closed_lab
from .deliverables import create_deliverables
from .sourcegen import generate_source_lab


def add_ai_credentials(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--key",
        nargs="?",
        const="__PROMPT__",
        help="OpenAI API key; omit the value to enter it securely",
    )
    command.add_argument("--model", help="OpenAI model ID (or use CVELAB_MODEL)")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="cvelab",
        description="Generate isolated, source-backed CVE reproduction labs.",
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

    source = sub.add_parser("source", help="Generate a lab from vulnerable and fixed source revisions")
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
    add_ai_credentials(auto)

    run = sub.add_parser("run", help="Build containers and validate both variants")
    run.add_argument("cve")
    run.add_argument("--keep", action="store_true", help="Keep containers running")

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

    all_cmd = sub.add_parser("all", help="Generate and validate a lab")
    all_cmd.add_argument("cve")
    all_cmd.add_argument("--cwe", help="Override CWE when public metadata is incomplete")
    all_cmd.add_argument("--ai", choices=("off", "auto", "on"), default="auto")
    add_ai_credentials(all_cmd)
    all_cmd.add_argument("--keep", action="store_true", help="Keep containers running")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        api_key = getattr(args, "key", None)
        if api_key == "__PROMPT__":
            api_key = getpass.getpass("OpenAI API key: ")
        model = getattr(args, "model", None)
        if args.command == "build":
            result = build_lab(args.cve, args.output_root, args.cwe, args.ai, api_key, model)
        elif args.command in {"source", "source-all", "auto"}:
            generated = generate_source_lab(
                args.cve,
                args.output_root,
                args.repo,
                args.fixed_ref,
                args.vulnerable_ref,
                api_key,
                model,
            )
            if args.command in {"source-all", "auto"} and generated.get("ok"):
                result = run_lab(args.cve, args.output_root, args.keep)
                if args.command == "auto":
                    result = create_deliverables(
                        args.cve.upper(),
                        args.output_root.resolve() / args.cve.upper(),
                        result,
                        api_key,
                        model,
                    )
            else:
                result = generated
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
            build_lab(args.cve, args.output_root, args.cwe, args.ai, api_key, model)
            result = run_lab(args.cve, args.output_root, args.keep)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok", True) else 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1
