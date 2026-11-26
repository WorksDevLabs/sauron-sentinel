"""Local read-only Windows exposure checks and redacted response validation."""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import pytest

from sauron_sentinel import windows_exposure


def sample_checks():
    return [
        {"Check": "Firewall", "Status": "OK", "Detail": "Enabled."},
        {"Check": "OpenSSH server", "Status": "REVIEW", "Detail": "Service running."},
        {"Check": "System drive encryption", "Status": "UNKNOWN", "Detail": "Unavailable."},
    ]


def test_parse_valid_audit_counts_without_security_claims():
    result = windows_exposure._parse_output(json.dumps(sample_checks()).encode())
    assert result["status"] == "completed"
    assert result["review_count"] == 1
    assert result["unknown_count"] == 1
    assert result["checks"][0] == {
        "name": "Firewall",
        "status": "OK",
        "detail": "Enabled.",
    }


@pytest.mark.parametrize(
    "invalid",
    [
        {},
        [],
        [{"Check": "Firewall", "Status": "SAFE", "Detail": "No issue"}],
        [{"Check": "Firewall", "Status": "OK", "Detail": 12}],
        [{"Check": "Firewall", "Status": "OK", "Detail": "x" * 501}],
        [{"Check": "Firewall", "Status": "OK", "Detail": "", "secret": "hidden"}],
    ],
)
def test_reject_invalid_audit_schema(invalid):
    with pytest.raises(ValueError):
        windows_exposure._parse_output(json.dumps(invalid).encode())


def test_reject_non_json_and_bad_encoding():
    for invalid in (b"not json", b"\xff\xfe\xfa", b"null"):
        with pytest.raises(ValueError):
            windows_exposure._parse_output(invalid)


def test_non_windows_is_explicitly_unavailable(monkeypatch):
    monkeypatch.setattr(windows_exposure.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        windows_exposure, "_powershell", lambda: pytest.fail("unexpected PowerShell lookup")
    )
    assert windows_exposure.run_exposure_audit() == {
        "status": "unavailable",
        "error": "not_windows",
        "checks": [],
    }


def test_missing_powershell_is_explicitly_unavailable(monkeypatch):
    monkeypatch.setattr(windows_exposure.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_exposure, "_powershell", lambda: None)
    assert windows_exposure.run_exposure_audit()["error"] == "powershell_unavailable"


def test_run_success_without_real_windows_access(monkeypatch):
    monkeypatch.setattr(windows_exposure.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_exposure, "_powershell", lambda: "powershell.exe")
    monkeypatch.setattr(
        windows_exposure,
        "_collect",
        lambda path: json.dumps(sample_checks()).encode() if path == "powershell.exe" else b"",
    )
    assert windows_exposure.run_exposure_audit()["review_count"] == 1


def test_collector_failure_does_not_leak_private_exception(monkeypatch):
    monkeypatch.setattr(windows_exposure.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_exposure, "_powershell", lambda: "powershell.exe")

    def fail(_):
        raise OSError("C:\\Users\\private\\secret.key")

    monkeypatch.setattr(windows_exposure, "_collect", fail)
    output = windows_exposure.run_exposure_audit()
    assert output == {"status": "unavailable", "error": "audit_failed", "checks": []}
    assert "private" not in str(output)


def test_packaged_powershell_matches_reviewed_readonly_script():
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts/windows-exposure-readonly.ps1").read_text(encoding="utf-8")
    packaged = (
        resources.files("sauron_sentinel")
        .joinpath("windows_exposure.ps1")
        .read_text(encoding="utf-8")
    )
    assert packaged.startswith(script.split("Write-Output 'Windows exposure: READ-ONLY")[0])
    assert "ConvertTo-Json -InputObject" in packaged
    assert "SAURON_EXPOSURE_JSON" in packaged


def _packaged_script() -> str:
    return (
        resources.files("sauron_sentinel")
        .joinpath("windows_exposure.ps1")
        .read_text(encoding="utf-8")
    )


def test_packaged_powershell_has_no_mutating_or_network_commands():
    script = _packaged_script()
    forbidden = re.compile(
        r"\b(?:Set-(?!StrictMode\b)\w+|Enable-\w+|Disable-\w+|Remove-\w+|Start-\w+|Stop-\w+"
        r"|Restart-\w+|Suspend-\w+|Install-\w+|Uninstall-\w+|Add-Mp\w+|Out-File"
        r"|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|New-NetFirewallRule)\b"
        r"|-Verb\s+RunAs",
        re.IGNORECASE,
    )
    assert forbidden.findall(script) == []


def test_firewall_profiles_and_default_inbound_are_separate_checks():
    script = _packaged_script()
    assert "Run-Check 'Firewall profiles'" in script
    assert "Run-Check 'Firewall default inbound'" in script
    assert "Run-Check 'Firewall' " not in script


def test_listener_and_encryption_results_avoid_unsupported_claims():
    script = _packaged_script()
    assert "A listener does not prove Internet exposure." in script
    encryption = script[script.index("Run-Check 'System drive encryption'") :]
    encryption = encryption[: encryption.index("Run-Check 'Windows Update service'")]
    # Only an explicit "Off" is a review item; unreadable status stays UNKNOWN.
    assert "$state -eq 'Off'" in encryption
    assert "'UNKNOWN' 'BitLocker status is not readable with standard user rights" in encryption


def test_dashboard_starts_audit_only_from_the_button():
    script = (
        resources.files("sauron_sentinel").joinpath("static", "app.js").read_text(encoding="utf-8")
    )
    calls = [line.strip() for line in script.splitlines() if "runExposure" in line]
    assert calls == [
        "async function runExposure() {",
        'node("system-exposure-button").addEventListener("click", runExposure);',
    ]
    assert script.count("/api/system-exposure") == 1
