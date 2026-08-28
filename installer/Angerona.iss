; Angerona protected migration wrapper.
; The signed MSIX is the repository-supported public first-install artifact.
; This non-public package can only delegate to an already installed,
; protected Angerona upgrade authority. It is not a clean-install path.

#ifndef ApprovedInstallationMigrationOnly
  #error Classic Setup must be explicitly compiled as approved-installation migration-only
#endif

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef ArtifactTag
  #define ArtifactTag "dev"
#endif
#ifndef PublisherCertificateSha256
  #define PublisherCertificateSha256 "UNCONFIGURED"
#endif

[Setup]
AppId={{6B6931E2-D992-4D4D-90D1-F2FEF5678BD3}
AppName=Angerona
AppVersion={#AppVersion}
AppPublisher=Angerona contributors
DefaultDirName={commonpf64}\Angerona
DefaultGroupName=Angerona
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableReadyPage=yes
LicenseFile=..\LICENSE
OutputDir=..
OutputBaseFilename=Angerona-{#ArtifactTag}-win64-migration-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The wrapper remains unelevated while it authenticates its own publisher and
; asks the already installed authority to verify custody. Only that protected
; authority requests elevation, and it repeats custody checks before mutation.
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayIcon={app}\Angerona.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
SignTool=AngeronaSign
CreateAppDir=no
CreateUninstallRegKey=no
Uninstallable=no
UsePreviousAppDir=no

[Files]
; The wrapper contains only the already threshold-authorized portable upgrade
; archive and checksum. Both are extracted to Setup's temporary directory; no
; application file is ever copied by Inno Setup.
Source: "..\Angerona-{#ArtifactTag}-win64.zip"; Flags: dontcopy
Source: "..\Angerona-{#ArtifactTag}-win64.zip.sha256"; Flags: dontcopy

[Code]
const
  PriorAuthorityRelative = 'Angerona\Install-Angerona-Release.ps1';

function VerifySetupPublisher(): Boolean;
var
  PowerShell, Parameters: String;
  ResultCode: Integer;
begin
  Result := False;
  if Length('{#PublisherCertificateSha256}') <> 64 then
    exit;
  SetEnvironmentVariable('ANGERONA_SETUP_PATH', ExpandConstant('{srcexe}'));
  SetEnvironmentVariable(
    'ANGERONA_EXPECTED_PUBLISHER_SHA256', '{#PublisherCertificateSha256}');
  PowerShell := ExpandConstant(
    '{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters :=
    '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command "' +
    '$s=Get-AuthenticodeSignature -LiteralPath $env:ANGERONA_SETUP_PATH;' +
    'if($s.Status -ne ''Valid'' -or $null -eq $s.SignerCertificate){exit 10};' +
    '$h=[Security.Cryptography.SHA256]::Create();try{' +
    '$a=(($h.ComputeHash($s.SignerCertificate.RawData)|' +
    'ForEach-Object{$_.ToString(''x2'')})-join '''')' +
    '}finally{$h.Dispose()};' +
    'if($a -ine $env:ANGERONA_EXPECTED_PUBLISHER_SHA256){exit 11}"';
  Result := Exec(
    PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and
    (ResultCode = 0);
  SetEnvironmentVariable('ANGERONA_SETUP_PATH', '');
  SetEnvironmentVariable('ANGERONA_EXPECTED_PUBLISHER_SHA256', '');
end;

function VerifyPriorApprovedInstallation(): Boolean;
var
  PowerShell, Installer, Parameters, PriorRoot: String;
  ResultCode: Integer;
begin
  Result := False;
  PriorRoot := ExpandConstant('{commonpf64}\Angerona');
  Installer := AddBackslash(PriorRoot) + 'Install-Angerona-Release.ps1';
  PowerShell := ExpandConstant(
    '{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters :=
    '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' +
    Installer + '" -CustodyPreflightOnly';
  Result := Exec(
    PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and
    (ResultCode = 0);
end;

function InitializeSetup(): Boolean;
begin
  Result := False;
  if not VerifySetupPublisher() then
  begin
    MsgBox('Setup publisher verification failed. Use the protected release ' +
      'verifier and run only the exact Authenticode-signed Angerona Setup.',
      mbCriticalError, MB_OK);
    exit;
  end;
  if not VerifyPriorApprovedInstallation() then
  begin
    MsgBox('Migration requires an existing Angerona installation whose protected ' +
      'upgrade authority, ACL custody, publisher pin, signed native verifier, and ' +
      'release evidence are intact. Clean installation is supported only by the ' +
      'signed MSIX.', mbCriticalError, MB_OK);
    exit;
  end;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  PowerShell, Installer, Archive, Parameters: String;
  ResultCode: Integer;
begin
  Result := '';
  try
    ExtractTemporaryFile('Angerona-{#ArtifactTag}-win64.zip');
    ExtractTemporaryFile('Angerona-{#ArtifactTag}-win64.zip.sha256');
    PowerShell := ExpandConstant(
      '{sys}\WindowsPowerShell\v1.0\powershell.exe');
    Installer := ExpandConstant('{commonpf64}\') + PriorAuthorityRelative;
    Archive := ExpandConstant('{tmp}\Angerona-{#ArtifactTag}-win64.zip');
    Parameters := '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' +
      Installer + '" -ReleaseArchive "' + Archive + '"';
    if not ShellExec(
        'runas', PowerShell, Parameters, '', SW_HIDE,
        ewWaitUntilTerminated, ResultCode) or
        (ResultCode <> 0) then
      Result := 'The protected installed upgrade authority rejected this migration. ' +
        'No Angerona application file was installed by Setup.';
  except
    Result := 'Migration preparation failed closed: ' + GetExceptionMessage;
  end;
end;
