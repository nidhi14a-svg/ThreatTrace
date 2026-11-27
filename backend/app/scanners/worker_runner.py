"""Dedicated Scanner Worker CLI and Runner.

Executes static analysis scanners (Semgrep, Bandit, Gitleaks, OSV-Scanner, Custom Rules)
against an isolated, read-only workspace directory and emits normalized, redacted results.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from app.core.security import redact_secrets
from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base_scanner import (
    BaseScanner,
    ScannerExecutionResult,
    ScannerStatus,
    aggregate_scanner_statuses,
)
from app.scanners.custom_rules.scanner import CustomRulesScanner
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.normalizer import normalize_scanner_result
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.suppression import apply_suppressions, deduplicate_findings

logger = logging.getLogger("scanner_worker")


def get_available_scanners(timeout: int = 60) -> dict[str, BaseScanner]:
    """Instantiate and return available scanners."""
    from app.scanners.custom_rules import default_registry, register_all_custom_rules
    register_all_custom_rules(default_registry)
    return {
        "semgrep": SemgrepScanner(timeout_seconds=timeout),
        "bandit": BanditScanner(timeout_seconds=timeout),
        "secrets": SecretsScanner(timeout_seconds=timeout),
        "dependency": DependencyScanner(timeout_seconds=timeout),
        "custom_rules": CustomRulesScanner(registry=default_registry, timeout=timeout),
    }


def check_tool_versions() -> dict[str, Any]:
    """Check availability and versions of static analysis tools."""
    tools: dict[str, Any] = {}
    import subprocess

    # Python version
    tools["python"] = {
        "available": True,
        "version": sys.version.split()[0],
    }

    # Semgrep
    try:
        res = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=30)
        tools["semgrep"] = {
            "available": res.returncode == 0,
            "version": res.stdout.strip() if res.returncode == 0 else None,
        }
    except Exception as e:
        tools["semgrep"] = {"available": False, "error": str(e)}

    # Bandit
    try:
        res = subprocess.run(["bandit", "--version"], capture_output=True, text=True, timeout=10)
        tools["bandit"] = {
            "available": res.returncode == 0,
            "version": res.stdout.strip() if res.returncode == 0 else None,
        }
    except Exception as e:
        tools["bandit"] = {"available": False, "error": str(e)}

    # Gitleaks
    try:
        res = subprocess.run(["gitleaks", "version"], capture_output=True, text=True, timeout=10)
        tools["gitleaks"] = {
            "available": res.returncode == 0,
            "version": res.stdout.strip() if res.returncode == 0 else None,
        }
    except Exception as e:
        tools["gitleaks"] = {"available": False, "error": str(e)}

    # OSV-Scanner
    try:
        res = subprocess.run(["osv-scanner", "--version"], capture_output=True, text=True, timeout=10)
        tools["osv_scanner"] = {
            "available": res.returncode == 0,
            "version": res.stdout.strip() if res.returncode == 0 else None,
        }
    except Exception as e:
        tools["osv_scanner"] = {"available": False, "error": str(e)}

    # Custom Rules Pack
    try:
        from app.scanners.custom_rules import ALL_CUSTOM_RULES, default_registry, register_all_custom_rules
        register_all_custom_rules(default_registry)
        tools["custom_rules"] = {
            "available": True,
            "rules_count": len(ALL_CUSTOM_RULES),
            "rules": [r.rule_id for r in ALL_CUSTOM_RULES],
        }
    except Exception as e:
        tools["custom_rules"] = {"available": False, "error": str(e)}

    return tools


async def run_scanners(
    workspace: str,
    selected_scanners: list[str],
    timeout: int = 60,
) -> dict[str, ScannerExecutionResult]:
    """Execute selected scanners against the workspace with isolated error handling."""
    all_scanners = get_available_scanners(timeout=timeout)
    results: dict[str, ScannerExecutionResult] = {}

    to_run: list[tuple[str, BaseScanner]] = []
    for name in selected_scanners:
        alias = name.strip().lower()
        if alias in ("all", "*"):
            for sname, scanner in all_scanners.items():
                to_run.append((sname, scanner))
            break
        elif alias in all_scanners:
            to_run.append((alias, all_scanners[alias]))
        elif alias in ("gitleaks", "detect_secrets"):
            to_run.append(("secrets", all_scanners["secrets"]))
        elif alias in ("osv", "osv-scanner", "dependencies"):
            to_run.append(("dependency", all_scanners["dependency"]))
        elif alias in ("custom", "rules", "custom-rules"):
            to_run.append(("custom_rules", all_scanners["custom_rules"]))
        else:
            logger.warning(f"Unknown scanner requested: {name}")

    # Remove duplicates preserving order
    seen: set[str] = set()
    deduped_run: list[tuple[str, BaseScanner]] = []
    for sname, scanner in to_run:
        if sname not in seen:
            seen.add(sname)
            deduped_run.append((sname, scanner))

    async def _execute_one(name: str, scanner: BaseScanner) -> tuple[str, ScannerExecutionResult]:
        try:
            res = await scanner.scan(workspace)
            return name, res
        except Exception as exc:
            logger.error(f"Scanner {name} failed with unhandled exception: {exc}")
            return name, scanner.create_result(
                status=ScannerStatus.FAILED,
                findings=[],
                duration_seconds=0.0,
                error=f"Unhandled scanner exception: {exc}",
            )

    # Run scanners concurrently
    tasks = [_execute_one(name, scanner) for name, scanner in deduped_run]
    task_results = await asyncio.gather(*tasks)

    for name, result in task_results:
        results[name] = result

    return results


def process_and_normalize_results(
    raw_results: dict[str, ScannerExecutionResult],
) -> dict[str, Any]:
    """Normalize findings, apply deduplication, suppression, and in-memory secret redaction."""
    all_findings: list[Any] = []

    for scanner_name, result in raw_results.items():
        if result.findings:
            normalized = normalize_scanner_result(result)
            all_findings.extend(normalized)

    # Deduplicate findings across tools
    deduped_findings, dedupe_log = deduplicate_findings(all_findings)

    # Filter suppressed findings (empty suppression rules by default)
    active_findings, suppression_log = apply_suppressions(deduped_findings, [])

    # Convert to dict and apply secret redaction
    final_finding_dicts: list[dict[str, Any]] = []
    for f in active_findings:
        f_dict = f.model_dump()
        if f_dict.get("evidence"):
            f_dict["evidence"] = redact_secrets(str(f_dict["evidence"]))
        if f_dict.get("message"):
            f_dict["message"] = redact_secrets(str(f_dict["message"]))
        final_finding_dicts.append(f_dict)

    # Calculate aggregated status
    aggregated_status = aggregate_scanner_statuses(list(raw_results.values())) if raw_results else "skipped"

    # Convert raw results to dict for JSON serialization
    serialized_results = {
        name: {
            "scanner_name": res.scanner_name,
            "status": str(res.status),
            "findings_count": len(res.findings),
            "duration_seconds": res.duration_seconds,
            "error": res.error,
        }
        for name, res in raw_results.items()
    }

    return {
        "status": aggregated_status,
        "scanners_executed": list(raw_results.keys()),
        "scanner_results": serialized_results,
        "findings": final_finding_dicts,
        "total_findings": len(final_finding_dicts),
        "deduplicated_count": len(dedupe_log),
        "suppressed_count": len(suppression_log),
    }


def main() -> int:
    """CLI Entrypoint for scanner worker."""
    parser = argparse.ArgumentParser(
        prog="threadtrace-scanner",
        description="Thread Trace Dedicated Scanner Worker CLI",
    )
    parser.add_argument(
        "--workspace",
        type=str,
        help="Path to workspace source directory to scan (read-only)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to write output results JSON file",
    )
    parser.add_argument(
        "--scanners",
        type=str,
        default="all",
        help="Comma-separated scanners to execute: semgrep,bandit,secrets,dependency,custom_rules,all",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-scanner execution timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check availability and versions of static analysis tools and exit",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output raw scanner findings instead of normalized findings",
    )

    args = parser.parse_args()

    if args.check_tools:
        tools = check_tool_versions()
        print(json.dumps(tools, indent=2))
        return 0

    if not args.workspace:
        parser.error("--workspace is required when not using --check-tools")

    workspace_path = Path(args.workspace).resolve()
    if not workspace_path.exists():
        error_output = {
            "status": "failed",
            "error": f"Workspace directory does not exist: {workspace_path}",
            "findings": [],
            "total_findings": 0,
        }
        print(json.dumps(error_output, indent=2), file=sys.stderr)
        return 1

    selected = [s.strip() for s in args.scanners.split(",") if s.strip()]
    start_time = time.time()

    # Execute scanners
    raw_results = asyncio.run(
        run_scanners(
            workspace=str(workspace_path),
            selected_scanners=selected,
            timeout=args.timeout,
        )
    )

    total_duration = round(time.time() - start_time, 3)

    if args.raw:
        payload = {
            "status": aggregate_scanner_statuses(list(raw_results.values())),
            "duration_seconds": total_duration,
            "scanner_results": {
                name: {
                    "scanner_name": res.scanner_name,
                    "status": str(res.status),
                    "findings": res.findings,
                    "duration_seconds": res.duration_seconds,
                    "error": res.error,
                }
                for name, res in raw_results.items()
            },
        }
    else:
        payload = process_and_normalize_results(raw_results)
        payload["duration_seconds"] = total_duration

    json_str = json.dumps(payload, indent=2)

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_str, encoding="utf-8")
        logger.info(f"Scan results written to {out_path}")
    else:
        print(json_str)

    return 0


if __name__ == "__main__":
    sys.exit(main())
