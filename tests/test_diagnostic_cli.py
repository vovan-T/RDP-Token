#!/usr/bin/env python3
import tempfile
from pathlib import Path
from unittest.mock import patch

from token_admin_test_support import load_diagnostic_cli


diagnostic_cli = load_diagnostic_cli()


def test_safe_object_excludes_sensitive_fields():
    result = diagnostic_cli._safe_object({
        "type": "certificate",
        "label": "RDP access",
        "fingerprint": "AA:BB",
        "private_key": "must-not-leak",
        "certificate_pem": "must-not-leak",
        "pin": "must-not-leak",
    })
    assert result == {
        "type": "certificate",
        "label": "RDP access",
        "fingerprint": "AA:BB",
    }


def test_diagnose_writes_sanitized_report():
    token = type("Token", (), {
        "reader": "Reader 0",
        "atr": "00",
        "vendor": "Test",
        "model": "Test token",
        "state": "READY",
        "error": "",
        "label": "LAB",
        "serial": "123",
        "user_pin_attempts": "10",
        "admin_pin_attempts": "10",
        "memory": "1 KB",
        "slot_id": "0",
        "key_options": [],
        "objects": [{
            "type": "certificate",
            "label": "Access",
            "certificate_pem": "must-not-leak",
            "private_key": "must-not-leak",
        }],
    })()
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "report.json"
        with patch.object(diagnostic_cli, "scan_inventory", return_value=([token], [])):
            assert diagnostic_cli.main([
                "--diagnose", "--quiet", "--report", str(report),
            ]) == 0
        content = report.read_text(encoding="utf-8")
        assert '"schema": "rdp-token-diagnostics/v1"' in content
        assert "must-not-leak" not in content


if __name__ == "__main__":
    test_safe_object_excludes_sensitive_fields()
    test_diagnose_writes_sanitized_report()
    print("diagnostic CLI tests passed")
