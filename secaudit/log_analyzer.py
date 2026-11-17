"""Authentication-log analysis for repeated failed login attempts."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class BruteForceFinding:
    """A source IP with at least the configured number of failures."""

    ip: str
    attempts: int
    lines: tuple[int, ...]


class LogAnalyzerError(Exception):
    """Base exception for log-analysis failures."""


class LogAnalyzer:
    """Analyze common Linux authentication logs without loading them in memory."""

    _FAILED = re.compile(
        r"(?:failed password|authentication failure|invalid user|failed login)",
        re.IGNORECASE,
    )
    _IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, threshold: int = 5) -> None:
        if threshold < 1:
            raise ValueError("threshold must be positive")
        self.threshold = threshold

    def analyze(self, path: Path) -> list[BruteForceFinding]:
        """Return IPs with repeated failed logins, preserving source line numbers."""
        failures: defaultdict[str, list[int]] = defaultdict(list)
        try:
            for number, line in self._read_lines(path):
                if not self._FAILED.search(line):
                    continue
                match = self._IP.search(line)
                if match:
                    failures[match.group()].append(number)
        except OSError as exc:
            raise LogAnalyzerError(f"cannot read log '{path}': {exc}") from exc

        return [
            BruteForceFinding(ip, len(lines), tuple(lines))
            for ip, lines in sorted(failures.items())
            if len(lines) >= self.threshold
        ]

    @staticmethod
    def _read_lines(path: Path) -> Iterator[tuple[int, str]]:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            yield from enumerate(stream, start=1)
