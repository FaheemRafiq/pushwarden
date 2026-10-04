; Inno Setup script for PushWarden-Setup.exe (per user, no administrator rights).
; Build on Windows:  iscc /DAppVersion=0.1.0 /DDist=..\..\dist installers\windows\pushwarden.iss
; Expects pushwarden-windows-amd64.exe and pushwarden-windows-arm64.exe in Dist.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Dist
  #define Dist "..\..\dist"
#endif

[Setup]
; AppId must never change: it is how upgrades find the existing install.
AppId={{80093AE4-7F84-4E03-B011-8076E6A59081}
AppName=PushWarden
AppVersion={#AppVersion}
AppPublisher=PushWarden
AppPublisherURL=https://github.com/FaheemRafiq/pushwarden
DefaultDirName={localappdata}\Programs\PushWarden
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible or arm64
ArchitecturesInstallIn64BitMode=x64compatible or arm64
MinVersion=10.0
OutputDir={#Dist}
OutputBaseFilename=PushWarden-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=PushWarden
UninstallDisplayIcon={app}\pushwarden.exe

[Tasks]
Name: "blockc2"; Description: "Block the PolinRider command servers in Windows Firewall (asks for administrator rights)"; Flags: checkedonce

[Files]
Source: "{#Dist}\pushwarden-windows-amd64.exe"; DestDir: "{app}"; DestName: "pushwarden.exe"; Check: not IsArm64; Flags: ignoreversion
Source: "{#Dist}\pushwarden-windows-arm64.exe"; DestDir: "{app}"; DestName: "pushwarden.exe"; Check: IsArm64; Flags: ignoreversion

[Icons]
; For people who do not use a terminal: the guided github-clean screens.
Name: "{autoprograms}\PushWarden"; Filename: "{app}\pushwarden.exe"; Parameters: "ui --pause"; Comment: "Check your GitHub repositories for PolinRider and clean them"

[Run]
Filename: "{app}\pushwarden.exe"; Parameters: "install --unattended --no-block-c2"; Flags: runhidden waituntilterminated; StatusMsg: "Starting PushWarden protection..."
Filename: "{app}\pushwarden.exe"; Parameters: "protect --install"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated skipifsilent; Tasks: blockc2; StatusMsg: "Blocking the PolinRider command servers..."

[UninstallRun]
Filename: "{app}\pushwarden.exe"; Parameters: "protect --uninstall"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated; RunOnceId: "UninstallNetBlock"
Filename: "{app}\pushwarden.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallGuard"

[UninstallDelete]
; left by self-update
Type: files; Name: "{app}\pushwarden.exe.old"
Type: files; Name: "{app}\pushwarden.exe.failed"
Type: filesandordirs; Name: "{app}\update"

[Code]
// The running guard locks pushwarden.exe: stop it before files are replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  rc: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "PushWarden Guard"', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM pushwarden.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(500);
  Result := '';
end;
