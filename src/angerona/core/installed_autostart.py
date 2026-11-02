"""Explicit, installed-only admin-at-logon enrollment; never requests elevation.

This is an enrolled administrator's interactive logon task, not a boot service
or PPL boundary. Source/legacy autostart never gains this task's authority.
All public operations are worker operations; a GUI must cache their results.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import ntpath
import os
import re
import sys
import tempfile
import time
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

_TASK_PREFIX = "AngeronaInstalledAdminLogon-"
_SOURCE = "Angerona.InstalledAdminLogon.v1"
_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
_MAX_OUTPUT = 65536
_MAX_REQUEST = 16384
_MAX_XML = 49152
_NATIVE_SECONDS = 20.0
_FULL = 0x001F01FF
_READ_EXECUTE = 0x001200A9
_BA = "S-1-5-32-544"
_SY = "S-1-5-18"
_CODES = frozenset({
    "enrolled", "enrolled-legacy-conflict", "not-enrolled", "enrolled-created",
    "revoked", "revoked-legacy-preserved", "source-or-platform-held", "package-authority-held",
    "modern-entry-held", "native-unavailable", "native-output-held", "native-retirement-held",
    "current-user-held", "initial-admin-required", "legacy-conflict", "task-definition-held",
    "task-security-held", "reenrollment-review", "native-race-held", "registration-unverified",
})


@dataclass(frozen=True)
class InstalledAutostartStatus:
    """Diagnostic facts, never permission to elevate or mutate.

    ``enabled=None`` means unproved. ``changed=False`` means no verified change;
    after a native failure it does not prove that registration had no effect.
    """

    code: str
    enabled: bool | None = None
    changed: bool = False
    requires_review: bool = False

    def __post_init__(self):
        if (type(self.code) is not str or self.code not in _CODES
                or (self.enabled is not None and type(self.enabled) is not bool)
                or any(type(value) is not bool for value in (self.changed, self.requires_review))):
            raise ValueError("invalid-installed-autostart-status")


@dataclass(frozen=True)
class _Binding:
    sid: str
    task: str
    executable: str
    arguments: str
    cwd: str
    full_name: str
    family_name: str

    @property
    def description(self):
        return _SOURCE + "|" + self.full_name + "|" + self.family_name


class _Held(RuntimeError):
    def __init__(self, code):
        if code not in _CODES:
            code = "native-unavailable"
        self.code = code
        super().__init__(code)


def _valid_sid(sid):
    if type(sid) is not str or len(sid) > 184 or not re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+){1,15}", sid):
        return False
    parts = sid.split("-")[2:]
    return (all(str(int(part)) == part for part in parts) and int(parts[0]) < 1 << 48
            and all(int(part) < 1 << 32 for part in parts[1:])
            and (sid.startswith("S-1-5-21-") or sid.startswith("S-1-12-1-")))


def _normal_path(value):
    if (type(value) is not str or not 1 <= len(value) <= 32767 or any(ord(ch) < 32 for ch in value)
            or not re.match(r"\A[A-Za-z]:[\\/]", value) or ":" in value[2:]):
        raise _Held("modern-entry-held")
    return ntpath.normcase(ntpath.normpath(value))


# Fixed code; the bounded JSON request crosses only a sanitized environment
# channel. No report/path/SID text is interpolated into PowerShell source.
_SCRIPT = r'''
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
function Write-Result($value) {
    $text=ConvertTo-Json -InputObject $value -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt 65536) { exit 22 }
    [Console]::WriteLine($text)
}
function Test-MissingTask($record) {
    $failure=$record.Exception
    for ($index=0; $index -lt 4 -and $null -ne $failure; $index++) {
        if ($failure.HResult -eq -2147024894) { return $true }
        $failure=$failure.InnerException
    }
    return $false
}
function Get-ExactXmlDigest([string]$xml) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($xml)))).Replace('-','').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}
function Read-Snapshot($folder,$name) {
    $task=$null
    try { $task=$folder.GetTask($name) } catch {
        if (-not (Test-MissingTask $_)) { throw }
    }
    $legacy=$false
    try { $null=$folder.GetTask('AngeronaAutostart'); $legacy=$true } catch {
        if (-not (Test-MissingTask $_)) { throw }
    }
    if ($null -eq $task) { return @{present=$false;legacy=$legacy;xml='';security=$null} }
    $xml=[string]$task.Xml
    if ($xml.Length -gt 49152) { throw 'bounded-xml' }
    $sddl=[string]$task.GetSecurityDescriptor(7)
    if ($sddl.Length -gt 8192) { throw 'bounded-security' }
    $sd=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    if ($null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -gt 16) { throw 'bounded-acl' }
    $aces=@()
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback) { throw 'unknown-ace' }
        $aces+=[ordered]@{sid=[string]$ace.SecurityIdentifier.Value;mask=[int]$ace.AccessMask;
            flags=[int]$ace.AceFlags;qualifier=[int]$ace.AceQualifier}
    }
    return @{present=$true;legacy=$legacy;xml=$xml;security=[ordered]@{
        owner=[string]$sd.Owner.Value;group=[string]$sd.Group.Value;
        protected=([int]$sd.ControlFlags -band 4096) -ne 0;aces=@($aces)}}
}
try {
    $encoded=$env:ANGERONA_INSTALLED_AUTOSTART_REQUEST
    if ($null -eq $encoded -or $encoded.Length -gt 24000) { exit 20 }
    $raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
    if ($raw.Length -gt 16384) { exit 20 }
    $request=ConvertFrom-Json -InputObject $raw
    if ($request.version -ne 1) { exit 20 }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $sid=[string]$identity.User.Value
        $admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
    if ($request.operation -ceq 'identity') { Write-Result @{sid=$sid;elevated=[bool]$admin}; exit 0 }
    if ($request.sid -cne $sid -or $request.task -cne ('AngeronaInstalledAdminLogon-'+$sid)) { exit 20 }
    if ($request.operation -notin @('inspect','enroll','revoke')) { exit 20 }
    $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
    $folder=$scheduler.GetFolder('\')
    if ($request.operation -ceq 'inspect') { Write-Result (Read-Snapshot $folder $request.task); exit 0 }
    if (-not $admin) { exit 21 }
    $before=Read-Snapshot $folder $request.task
    if ($request.operation -ceq 'revoke') {
        if (-not $before.present) { Write-Result @{snapshot=$before;changed=$false}; exit 0 }
        # Re-read exactly the snapshot Python just verified. DeleteTask has no
        # conditional-handle API; BA/SYSTEM races remain an administrator boundary.
        if ($request.expected_xml_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
            (Get-ExactXmlDigest $before.xml) -cne $request.expected_xml_sha256 -or
            (ConvertTo-Json -InputObject $before.security -Depth 8 -Compress) -cne $request.expected_security) { exit 23 }
        $folder.DeleteTask($request.task,0)
        Write-Result @{snapshot=(Read-Snapshot $folder $request.task);changed=$true}; exit 0
    }
    if ($before.present -or $before.legacy) { Write-Result @{snapshot=$before;changed=$false}; exit 0 }
    if ([IO.Path]::GetFileName($request.executable) -cne 'AngeronaSafeStart.exe' -or
        $request.arguments -cne '--automatic-start' -or
        [IO.Path]::GetDirectoryName($request.executable) -cne $request.cwd) { exit 20 }
    $definition=$scheduler.NewTask(0)
    $definition.RegistrationInfo.Source='Angerona.InstalledAdminLogon.v1'
    $definition.RegistrationInfo.Author=$sid
    $definition.RegistrationInfo.URI='\'+$request.task
    $definition.RegistrationInfo.Description=$request.description
    $definition.Principal.Id='AngeronaInstalled'
    $definition.Principal.UserId=$sid
    $definition.Principal.LogonType=3
    $definition.Principal.RunLevel=1
    $settings=$definition.Settings
    $settings.Compatibility=2; $settings.Enabled=$true; $settings.Hidden=$false
    $settings.MultipleInstances=2; $settings.AllowDemandStart=$false
    $settings.DisallowStartIfOnBatteries=$false; $settings.StopIfGoingOnBatteries=$false
    $settings.AllowHardTerminate=$false; $settings.StartWhenAvailable=$false
    $settings.RunOnlyIfNetworkAvailable=$false; $settings.RunOnlyIfIdle=$false
    $settings.WakeToRun=$false; $settings.ExecutionTimeLimit='PT0S'
    $settings.RestartCount=0; $settings.Priority=7
    $settings.IdleSettings.StopOnIdleEnd=$false; $settings.IdleSettings.RestartOnIdle=$false
    $trigger=$definition.Triggers.Create(9); $trigger.Enabled=$true; $trigger.UserId=$sid
    $definition.Actions.Context='AngeronaInstalled'
    $action=$definition.Actions.Create(0)
    $action.Path=$request.executable; $action.Arguments=$request.arguments; $action.WorkingDirectory=$request.cwd
    $sddl='O:BAG:SYD:P(A;;0x001f01ff;;;SY)(A;;0x001f01ff;;;BA)(A;;0x001200a9;;;'+$sid+')'
    # CREATE | DONT_ADD_PRINCIPAL_ACE | IGNORE_REGISTRATION_TRIGGERS.
    # No UPDATE/CREATE_OR_UPDATE, password, arbitrary command or task Run().
    $null=$folder.RegisterTaskDefinition($request.task,$definition,50,$sid,$null,3,$sddl)
    Write-Result @{snapshot=(Read-Snapshot $folder $request.task);changed=$true}
} catch { exit 24 }
'''


def _native(request):
    """Retain the exact hidden child Job until all output/descendants retire."""
    from angerona.core.privilege import sanitized_child_environment, trusted_powershell_path
    from angerona.startup import _WindowsProbe
    probe = None
    try:
        raw = json.dumps(dict(request, version=1), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(raw) > _MAX_REQUEST:
            raise _Held("native-output-held")
        executable = trusted_powershell_path()
        environment = sanitized_child_environment()
        environment["ANGERONA_INSTALLED_AUTOSTART_REQUEST"] = base64.b64encode(raw).decode("ascii")
        command = [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                   base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")]
        with tempfile.TemporaryFile(mode="w+b") as output:
            probe = _WindowsProbe(command, cwd=str(executable.parent), env=environment, stdout=output)
            deadline = time.monotonic() + _NATIVE_SECONDS
            while probe.poll() is None:
                if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > _MAX_OUTPUT:
                    raise _Held("native-output-held")
                time.sleep(0.05)
            if not probe.wait_tree(timeout=1.0):
                raise _Held("native-retirement-held")
            result = probe.returncode
            retiring, probe = probe, None
            try:
                retiring.close()
            except Exception:
                raise _Held("native-retirement-held") from None
            if result != 0:
                raise _Held({20: "native-output-held", 21: "initial-admin-required",
                             22: "native-output-held", 23: "native-race-held"}.get(result, "native-unavailable"))
            output.seek(0)
            data = output.read(_MAX_OUTPUT + 1)
            if len(data) > _MAX_OUTPUT:
                raise _Held("native-output-held")
            value = json.loads(data.decode("utf-8-sig"))
            if type(value) is not dict:
                raise _Held("native-output-held")
            return value
    except _Held:
        raise
    except Exception:
        raise _Held("native-unavailable") from None
    finally:
        if probe is not None:
            retiring, probe = probe, None
            try:
                retiring.close()
            except Exception:
                raise _Held("native-retirement-held") from None


def _binding(*, require_admin=False):
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        raise _Held("source-or-platform-held")
    from angerona.core.windows_package_identity import verify_current_msix_authority
    authority = verify_current_msix_authority()
    if authority.trusted is not True or authority.identity is None:
        raise _Held("package-authority-held")
    from angerona.core.autostart import _target_action
    try:
        executable, arguments, cwd = _target_action()
    except Exception:
        raise _Held("modern-entry-held") from None
    if (ntpath.basename(executable) != "AngeronaSafeStart.exe" or arguments != "--automatic-start"
            or _normal_path(ntpath.dirname(executable)) != _normal_path(cwd)):
        raise _Held("modern-entry-held")
    identity = _native({"operation": "identity"})
    if (set(identity) != {"sid", "elevated"} or not _valid_sid(identity.get("sid"))
            or type(identity.get("elevated")) is not bool):
        raise _Held("current-user-held")
    if require_admin:
        from angerona.core.privilege import is_admin
        if identity["elevated"] is not True or is_admin() is not True:
            raise _Held("initial-admin-required")
    return _Binding(identity["sid"], _TASK_PREFIX + identity["sid"], executable, arguments, cwd,
                    authority.identity.full_name, authority.identity.family_name)


def _request(binding, operation):
    return {"operation": operation, "sid": binding.sid, "task": binding.task,
            "executable": binding.executable, "arguments": binding.arguments, "cwd": binding.cwd,
            "description": binding.description}


def _child(parent, name, *, required=True):
    values = parent.findall(_NS + name)
    if len(values) != 1:
        if not required and not values:
            return None
        raise _Held("task-definition-held")
    return values[0]


def _text(parent, name, *, required=True):
    value = _child(parent, name, required=required)
    if value is None:
        return ""
    if list(value) or value.attrib:
        raise _Held("task-definition-held")
    return (value.text or "").strip()


def _verify_xml(payload, binding):
    if type(payload) is not str or not 1 <= len(payload) <= _MAX_XML:
        raise _Held("task-definition-held")
    try:
        root = ET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException, ValueError):
        raise _Held("task-definition-held") from None
    if (root.tag != _NS + "Task" or len(list(root.iter())) > 128
            or any(not node.tag.startswith(_NS) for node in root.iter())
            or any(node.tag not in {_NS + name for name in
                   ("RegistrationInfo", "Triggers", "Principals", "Settings", "Actions")} for node in root)):
        raise _Held("task-definition-held")
    registration = _child(root, "RegistrationInfo")
    if (_text(registration, "Source") != _SOURCE or _text(registration, "Author") != binding.sid
            or _text(registration, "URI") != "\\" + binding.task):
        raise _Held("task-definition-held")
    if _text(registration, "Description") != binding.description:
        raise _Held("reenrollment-review")
    principals = _child(root, "Principals")
    if len(list(principals)) != 1:
        raise _Held("task-definition-held")
    principal = _child(principals, "Principal")
    if (principal.attrib != {"id": "AngeronaInstalled"}
            or set(node.tag for node in principal) != {_NS + key for key in ("UserId", "LogonType", "RunLevel")}
            or _text(principal, "UserId") != binding.sid
            or _text(principal, "LogonType") != "InteractiveToken"
            or _text(principal, "RunLevel") != "HighestAvailable"):
        raise _Held("task-definition-held")
    triggers = _child(root, "Triggers")
    if len(list(triggers)) != 1:
        raise _Held("task-definition-held")
    trigger = _child(triggers, "LogonTrigger")
    if (any(node.tag not in {_NS + "UserId", _NS + "Enabled", _NS + "Delay"} for node in trigger)
            or _text(trigger, "UserId") != binding.sid or _text(trigger, "Enabled") != "true"
            or _text(trigger, "Delay", required=False) not in {"", "PT0S"}):
        raise _Held("task-definition-held")
    actions = _child(root, "Actions")
    if actions.attrib != {"Context": "AngeronaInstalled"} or len(list(actions)) != 1:
        raise _Held("task-definition-held")
    action = _child(actions, "Exec")
    if set(node.tag for node in action) != {_NS + name for name in ("Command", "Arguments", "WorkingDirectory")}:
        raise _Held("task-definition-held")
    if (_normal_path(_text(action, "Command")) != _normal_path(binding.executable)
            or _text(action, "Arguments") != binding.arguments
            or _normal_path(_text(action, "WorkingDirectory")) != _normal_path(binding.cwd)):
        raise _Held("reenrollment-review")
    settings = _child(root, "Settings")
    expected = {"MultipleInstancesPolicy": "IgnoreNew", "DisallowStartIfOnBatteries": "false",
        "StopIfGoingOnBatteries": "false", "AllowHardTerminate": "false", "StartWhenAvailable": "false",
        "RunOnlyIfNetworkAvailable": "false", "AllowStartOnDemand": "false", "Enabled": "true",
        "Hidden": "false", "RunOnlyIfIdle": "false", "WakeToRun": "false", "ExecutionTimeLimit": "PT0S", "Priority": "7"}
    for name, value in expected.items():
        if _text(settings, name) != value:
            raise _Held("task-definition-held")
    idle = _child(settings, "IdleSettings")
    if _text(idle, "StopOnIdleEnd") != "false" or _text(idle, "RestartOnIdle") != "false":
        raise _Held("task-definition-held")
    if (any(node.tag not in {_NS + name for name in (*expected, "IdleSettings")} for node in settings)
            or any(node.tag not in {_NS + name for name in ("Duration", "WaitTimeout", "StopOnIdleEnd", "RestartOnIdle")} for node in idle)):
        raise _Held("task-definition-held")


def _verify_security(value, binding):
    if (type(value) is not dict or set(value) != {"owner", "group", "protected", "aces"}
            or type(value["owner"]) is not str or type(value["group"]) is not str
            or value["owner"] not in {_BA, _SY} or value["group"] not in {_BA, _SY}
            or value["protected"] is not True or type(value["aces"]) is not list or len(value["aces"]) != 3):
        raise _Held("task-security-held")
    expected, seen = {_SY: _FULL, _BA: _FULL, binding.sid: _READ_EXECUTE}, set()
    for ace in value["aces"]:
        if (type(ace) is not dict or set(ace) != {"sid", "mask", "flags", "qualifier"}
                or type(ace["sid"]) is not str or ace["sid"] in seen or ace["sid"] not in expected
                or any(type(ace[name]) is not int for name in ("mask", "flags", "qualifier"))
                or ace["mask"] != expected[ace["sid"]] or ace["flags"] != 0 or ace["qualifier"] != 0):
            raise _Held("task-security-held")
        seen.add(ace["sid"])


def _verified_snapshot(snapshot, binding):
    if (type(snapshot) is not dict or set(snapshot) != {"present", "legacy", "xml", "security"}
            or type(snapshot["present"]) is not bool or type(snapshot["legacy"]) is not bool):
        raise _Held("native-output-held")
    if snapshot["present"]:
        _verify_xml(snapshot["xml"], binding)
        _verify_security(snapshot["security"], binding)
    elif snapshot["xml"] != "" or snapshot["security"] is not None:
        raise _Held("native-output-held")
    return snapshot


def _status(snapshot):
    if snapshot["present"]:
        return InstalledAutostartStatus("enrolled-legacy-conflict" if snapshot["legacy"] else "enrolled", enabled=True,
                                        requires_review=snapshot["legacy"])
    return InstalledAutostartStatus("legacy-conflict" if snapshot["legacy"] else "not-enrolled", enabled=False,
                                    requires_review=snapshot["legacy"])


def _operation_result(result, binding):
    if (type(result) is not dict or set(result) != {"snapshot", "changed"}
            or type(result["changed"]) is not bool):
        raise _Held("native-output-held")
    return _verified_snapshot(result["snapshot"], binding), result["changed"]


def inspect_enrollment() -> InstalledAutostartStatus:
    """Read native current-user task facts. Never elevates, registers or repairs."""
    try:
        binding = _binding()
        return _status(_verified_snapshot(_native(_request(binding, "inspect")), binding))
    except _Held as error:
        return InstalledAutostartStatus(error.code, requires_review=True)
    except Exception:
        return InstalledAutostartStatus("native-unavailable", requires_review=True)


def enroll_current_admin() -> InstalledAutostartStatus:
    """Explicit enrollment under an already-admin token; never requests UAC."""
    try:
        binding = _binding(require_admin=True)
        before = _verified_snapshot(_native(_request(binding, "inspect")), binding)
        if before["present"] or before["legacy"]:
            return _status(before)
        # Re-prove package/helper/admin/SID after the query may have blocked.
        if _binding(require_admin=True) != binding:
            raise _Held("native-race-held")
        after, changed = _operation_result(_native(_request(binding, "enroll")), binding)
        if not after["present"]:
            return _status(after) if after["legacy"] else InstalledAutostartStatus("registration-unverified", requires_review=True)
        if not changed:
            return _status(after)
        return InstalledAutostartStatus("enrolled-created", enabled=True, changed=True,
                                        requires_review=after["legacy"])
    except _Held as error:
        return InstalledAutostartStatus(error.code, requires_review=True)
    except Exception:
        return InstalledAutostartStatus("registration-unverified", requires_review=True)


def revoke_current_admin() -> InstalledAutostartStatus:
    """Remove only a verified same enrollment. Never stop its running app."""
    try:
        binding = _binding(require_admin=True)
        before = _verified_snapshot(_native(_request(binding, "inspect")), binding)
        if not before["present"]:
            return _status(before)
        if _binding(require_admin=True) != binding:
            raise _Held("native-race-held")
        request = _request(binding, "revoke")
        # Exact original string bytes, without trimming, parsing/serialization
        # or BOM/newline normalization. The native fresh snapshot repeats it.
        request.update(expected_xml_sha256=hashlib.sha256(before["xml"].encode("utf-8")).hexdigest(),
                       expected_security=json.dumps(before["security"], separators=(",", ":")))
        after, changed = _operation_result(_native(request), binding)
        if after["present"]:
            raise _Held("native-race-held")
        if not changed:
            return _status(after)
        return InstalledAutostartStatus("revoked-legacy-preserved" if after["legacy"] else "revoked", enabled=False, changed=True,
                                        requires_review=after["legacy"])
    except _Held as error:
        return InstalledAutostartStatus(error.code, requires_review=True)
    except Exception:
        return InstalledAutostartStatus("native-unavailable", requires_review=True)
