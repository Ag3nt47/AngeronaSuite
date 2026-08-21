; Angerona one-click Windows release installer.
; Compiled by the pinned GitHub release workflow on windows-latest.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef ArtifactTag
  #define ArtifactTag "dev"
#endif

[Setup]
AppId={{6B6931E2-D992-4D4D-90D1-F2FEF5678BD3}
AppName=Angerona
AppVersion={#AppVersion}
AppPublisher=Angerona contributors
DefaultDirName={autopf}\Angerona
DefaultGroupName=Angerona
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..
OutputBaseFilename=Angerona-{#ArtifactTag}-win64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
UninstallDisplayIcon={app}\Angerona.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Files]
Source: "..\dist\Angerona\Angerona.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Angerona\AngeronaBlackBox.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Angerona\release-files.sha256"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Angerona\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Angerona\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\Angerona\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\dist\Angerona\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\dist\Angerona\playbooks\*"; DestDir: "{app}\playbooks"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "guidedsetup"; Description: "Open Angerona Full Setup after installation"; GroupDescription: "First run:"; Flags: checkedonce

[Icons]
Name: "{autoprograms}\Angerona"; Filename: "{app}\Angerona.exe"; WorkingDir: "{app}"
Name: "{autoprograms}\Angerona Full Setup"; Filename: "{app}\Angerona.exe"; Parameters: "--setup"; WorkingDir: "{app}"
Name: "{autodesktop}\Angerona"; Filename: "{app}\Angerona.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\Angerona.exe"; Parameters: "--setup"; Description: "Open Angerona Full Setup"; Flags: postinstall nowait skipifsilent; Tasks: guidedsetup
Filename: "{app}\Angerona.exe"; Description: "Launch Angerona"; Flags: postinstall nowait skipifsilent; Tasks: not guidedsetup

[Code]
const
  VersionStateKey = 'Software\Angerona';
  VersionStateName = 'HighestInstalledVersion';
  UninstallStateKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6B6931E2-D992-4D4D-90D1-F2FEF5678BD3}_is1';

function TakeVersionPart(var Remaining: String; var Part: Word): Boolean;
var
  DotAt, Parsed: Integer;
  Token: String;
begin
  DotAt := Pos('.', Remaining);
  if DotAt > 0 then
  begin
    Token := Copy(Remaining, 1, DotAt - 1);
    Delete(Remaining, 1, DotAt);
  end
  else
  begin
    Token := Remaining;
    Remaining := '';
  end;
  Parsed := StrToIntDef(Token, -1);
  Result := (Token <> '') and (Parsed >= 0) and (Parsed <= 65535);
  if Result then
    Part := Parsed;
end;

function ParseVersion(const Value: String; var Packed: Int64): Boolean;
var
  Remaining: String;
  Major, Minor, Build, Revision: Word;
begin
  Remaining := Value;
  Major := 0;
  Minor := 0;
  Build := 0;
  Revision := 0;
  Result := TakeVersionPart(Remaining, Major);
  if Result and (Remaining <> '') then
    Result := TakeVersionPart(Remaining, Minor);
  if Result and (Remaining <> '') then
    Result := TakeVersionPart(Remaining, Build);
  if Result and (Remaining <> '') then
    Result := TakeVersionPart(Remaining, Revision);
  Result := Result and (Remaining = '');
  if Result then
    Packed := PackVersionComponents(Major, Minor, Build, Revision);
end;

function ReadHighestInstalledVersion(var Value: String): Boolean;
begin
  Result := RegQueryStringValue(HKLM64, VersionStateKey, VersionStateName, Value);
  if not Result then
    Result := RegQueryStringValue(HKLM64, UninstallStateKey, 'DisplayVersion', Value);
end;

function InitializeSetup(): Boolean;
var
  CurrentText, HighestText: String;
  CurrentVersion, HighestVersion: Int64;
begin
  Result := False;
  CurrentText := '{#AppVersion}';
  if not ParseVersion(CurrentText, CurrentVersion) then
  begin
    MsgBox('Setup has an invalid release version and cannot continue.', mbCriticalError, MB_OK);
    exit;
  end;
  if ReadHighestInstalledVersion(HighestText) then
  begin
    if not ParseVersion(HighestText, HighestVersion) then
    begin
      MsgBox('The protected Angerona version record is invalid. Setup will fail closed. ' +
        'Use the separately audited recovery process instead of bypassing this check.',
        mbCriticalError, MB_OK);
      exit;
    end;
    if ComparePackedVersion(CurrentVersion, HighestVersion) < 0 then
    begin
      MsgBox('Downgrade blocked: this Setup is Angerona ' + CurrentText +
        ', but version ' + HighestText + ' has already been installed.' + #13#10 + #13#10 +
        'Install an equal or newer signed release. Intentional rollback requires the ' +
        'separately audited recovery process.', mbCriticalError, MB_OK);
      exit;
    end;
  end;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not RegWriteStringValue(
      HKLM64, VersionStateKey, VersionStateName, '{#AppVersion}') then
      RaiseException('Could not persist the protected installed-version record.');
  end;
end;
