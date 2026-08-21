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

[Icons]
Name: "{autoprograms}\Angerona"; Filename: "{app}\Angerona.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Angerona"; Filename: "{app}\Angerona.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\Angerona.exe"; Description: "Launch Angerona"; Flags: postinstall nowait skipifsilent
