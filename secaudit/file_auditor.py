"""Filesystem checks for risky permissions and exposed configuration files."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileFinding:
    """A filesystem issue found during an audit."""

    path: Path
    issue: str
    detail: str


class FileAuditorError(Exception):
    """Base exception for filesystem-audit failures."""


class FileAuditor:
    """Scan regular files while avoiding symlink traversal."""

    _SENSITIVE_NAMES = {
        ".env",
        ".env.local",
        ".env.production",
        "config.php",
        "credentials",
        "credentials.json",
        "id_rsa",
        "id_rsa.pem",
        "secrets.json",
        "settings.py",
        "web.config",
    }
    _SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")

    def __init__(self, target: Path) -> None:
        self.target = target.expanduser()

    def audit(self) -> list[FileFinding]:
        """Return findings for world-writable files and exposed sensitive files."""
        if not self.target.exists():
            raise FileAuditorError(f"target does not exist: '{self.target}'")
        if not self.target.is_dir():
            raise FileAuditorError(f"target is not a directory: '{self.target}'")

        findings: list[FileFinding] = []
        try:
            for root, dirs, files in os.walk(
                self.target, followlinks=False, onerror=self._raise_os_error
            ):
                dirs[:] = [name for name in dirs if not (Path(root) / name).is_symlink()]
                for name in files:
                    path = Path(root) / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    findings.extend(self._audit_file(path))
        except OSError as exc:
            raise FileAuditorError(f"cannot scan '{self.target}': {exc}") from exc
        return findings

    @staticmethod
    def _raise_os_error(error: OSError) -> None:
        raise error

    def _audit_file(self, path: Path) -> list[FileFinding]:
        findings: list[FileFinding] = []
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise FileAuditorError(f"cannot inspect '{path}': {exc}") from exc

        if os.name != "nt":
            if mode & stat.S_IWOTH:
                findings.append(FileFinding(path, "world-writable", "any local user can modify it"))
            if self._is_sensitive(path) and mode & (stat.S_IROTH | stat.S_IWOTH):
                findings.append(
                    FileFinding(
                        path, "exposed-sensitive-file", "sensitive file is readable by others"
                    )
                )
        return findings

    def _is_sensitive(self, path: Path) -> bool:
        name = path.name.lower()
        return name in self._SENSITIVE_NAMES or name.endswith(self._SENSITIVE_SUFFIXES)
