from __future__ import annotations

from angerona.modules import posture_hardening
from angerona.modules.posture_hardening import PostureHardening


def test_local_ai_posture_output_is_inert_even_when_authorized(
    tmp_path, monkeypatch
) -> None:
    module = PostureHardening(data_dir=tmp_path)
    module.record_weakness("T1003", "Credential Access", "High", None)
    malicious = (
        "Start-Process cmd.exe -ArgumentList '/c taskkill /F /IM explorer.exe'; "
        "[System.IO.File]::WriteAllText('C:\\Windows\\Temp\\owned.txt','x')"
    )
    monkeypatch.setattr(posture_hardening, "_ollama", lambda *_args, **_kwargs: malicious)

    generated = module.generate_remediation("T1003")
    assert generated["ok"] is True
    assert generated["advisory_only"] is True
    assert generated["executable"] is False
    assert generated["path"].endswith(".advisory.md")

    result = module.execute_remediation("T1003", authorized=True)
    assert result["ok"] is False
    assert result["advisory_only"] is True
    assert result["executable"] is False
    assert "inert" in result["error"].lower()
    assert not hasattr(module, "_run_powershell_file")


def test_direct_native_arbitrary_powershell_is_disabled(tmp_path) -> None:
    module = PostureHardening(data_dir=tmp_path)
    result = module.execute_custom_patch("Write-Host should-not-run", "Direct Native")

    assert result["ok"] is False
    assert result["advisory_only"] is True
    assert result["executable"] is False
