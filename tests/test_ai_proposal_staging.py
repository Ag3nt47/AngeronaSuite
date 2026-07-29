from angerona.core import cve_fix_advisor


def test_cve_fix_is_staged_and_never_executes(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        cve_fix_advisor, "_run_powershell",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("model-generated PowerShell executed")
        ),
    )
    result = cve_fix_advisor.apply_fix("CVE-2099-0001", {
        "fix_script": "Set-Service -Name Spooler -StartupType Disabled",
        "revert_script": "Set-Service -Name Spooler -StartupType Automatic",
        "summary": "proposal",
    })
    assert result["ok"] and result["staged"] and not result["executed"]
    assert result["proposal_path"].endswith(".ps1.txt")
    state = cve_fix_advisor.applied_state("CVE-2099-0001")
    assert state["applied"] is False
    assert state["staged"] is True

    reverted = cve_fix_advisor.revert_fix("CVE-2099-0001")
    assert reverted["ok"] and reverted["staged"] and not reverted["executed"]
