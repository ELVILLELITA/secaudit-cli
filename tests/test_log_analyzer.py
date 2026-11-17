from pathlib import Path

from secaudit.log_analyzer import LogAnalyzer


def test_detects_repeated_failed_logins(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "\n".join(
            f"Jan 1 host sshd: Failed password for root from 192.0.2.10 port 22"
            for _ in range(3)
        ),
        encoding="utf-8",
    )

    finding = LogAnalyzer(threshold=3).analyze(log)

    assert [(item.ip, item.attempts) for item in finding] == [("192.0.2.10", 3)]
