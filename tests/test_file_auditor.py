import os
from pathlib import Path

import pytest

from secaudit.file_auditor import FileAuditor


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_detects_exposed_sensitive_file(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("TOKEN=secret", encoding="utf-8")
    target.chmod(0o644)

    findings = FileAuditor(tmp_path).audit()

    assert any(item.issue == "exposed-sensitive-file" for item in findings)
