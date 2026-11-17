"""Command-line interface for SecAudit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .file_auditor import FileAuditor, FileAuditorError
from .log_analyzer import LogAnalyzer, LogAnalyzerError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secaudit",
        description="Audit authentication logs and local file exposure.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    log = subparsers.add_parser("logs", help="detect repeated failed logins")
    log.add_argument("path", type=Path, help="authentication log path")
    log.add_argument("-t", "--threshold", type=int, default=5, help="failures per IP (default: 5)")

    files = subparsers.add_parser("files", help="audit file permissions and configurations")
    files.add_argument("path", type=Path, help="directory to scan")
    return parser


def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "logs":
            findings = LogAnalyzer(args.threshold).analyze(args.path)
            if not findings:
                print("No brute-force patterns detected.")
            for finding in findings:
                lines = ", ".join(map(str, finding.lines))
                print(f"[HIGH] {finding.ip}: {finding.attempts} failed logins (lines: {lines})")
            return 0

        findings = FileAuditor(args.path).audit()
        if not findings:
            print("No insecure files detected.")
        for finding in findings:
            print(f"[HIGH] {finding.issue}: {finding.path} ({finding.detail})")
        return 0
    except (FileAuditorError, LogAnalyzerError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
