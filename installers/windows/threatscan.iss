; Inno Setup script for ThreatScan-Setup.exe (per user, no administrator rights).
; Build on Windows:  iscc /DAppVersion=0.1.0 /DDist=..\..\dist installers\windows\threatscan.iss
; Expects threatscan-windows-amd64.exe and threatscan-windows-arm64.exe in Dist.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Dist
  #define Dist "..\..\dist"
#endif

[Setup]
; AppId must never change: it is how upgrades find the existing install.
AppId={{EA678DA5-0A02-43AA-9E2D-64FF78ADC859}
AppName=ThreatScan
AppVersion={#AppVersion}
AppPublisher=ThreatScan
AppPublisherURL=https://github.com/FaheemRafiq/threatscan
DefaultDirName={localappdata}\Programs\ThreatScan
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible or arm64
ArchitecturesInstallIn64BitMode=x64compatible or arm64
MinVersion=10.0
OutputDir={#Dist}
OutputBaseFilename=ThreatScan-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=ThreatScan
UninstallDisplayIcon={app}\threatscan.exe

[Tasks]
Name: "blockc2"; Description: "Block the PolinRider command servers in Windows Firewall (asks for administrator rights)"; Flags: checkedonce

[Files]
Source: "{#Dist}\threatscan-windows-amd64.exe"; DestDir: "{app}"; DestName: "threatscan.exe"; Check: not IsArm64; Flags: ignoreversion
Source: "{#Dist}\threatscan-windows-arm64.exe"; DestDir: "{app}"; DestName: "threatscan.exe"; Check: IsArm64; Flags: ignoreversion

[Icons]
; For people who do not use a terminal: the guided github-clean screens.
Name: "{autoprograms}\ThreatScan"; Filename: "{app}\threatscan.exe"; Parameters: "ui --pause"; Comment: "Check your GitHub repositories for PolinRider and clean them"

[Run]
Filename: "{app}\threatscan.exe"; Parameters: "install --unattended --no-block-c2"; Flags: runhidden waituntilterminated; StatusMsg: "Starting ThreatScan protection..."
Filename: "{app}\threatscan.exe"; Parameters: "protect --install"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated skipifsilent; Tasks: blockc2; StatusMsg: "Blocking the PolinRider command servers..."

[UninstallRun]
Filename: "{app}\threatscan.exe"; Parameters: "protect --uninstall"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated; RunOnceId: "UninstallNetBlock"
Filename: "{app}\threatscan.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallGuard"

[UninstallDelete]
; left by self-update
Type: files; Name: "{app}\threatscan.exe.old"
Type: files; Name: "{app}\threatscan.exe.failed"
Type: filesandordirs; Name: "{app}\update"

[Code]
// The running guard locks threatscan.exe: stop it before files are replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  rc: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "ThreatScan Guard"', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM threatscan.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(500);
  Result := '';
end;
