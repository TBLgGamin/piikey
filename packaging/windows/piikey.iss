; piikey installer (Inno Setup 6), per user: no admin rights, no system-wide changes.
; packaging/windows/package.ps1 compiles it and passes the three values below.

#ifndef AppVersion
  #error AppVersion is not defined: pass /DAppVersion=x.y.z (packaging/windows/package.ps1 does)
#endif
#ifndef SourceDir
  #error SourceDir is not defined: pass /DSourceDir=<release folder> (packaging/windows/package.ps1 does)
#endif
#ifndef OutputDir
  #error OutputDir is not defined: pass /DOutputDir=<folder> (packaging/windows/package.ps1 does)
#endif

[Setup]
; Fixed for the life of the project: upgrades and the uninstaller entry find the install by this id.
AppId={{8F0C2B6E-5D4A-4C1B-9E37-2A6F1D9B7C55}
AppName=piikey
AppVersion={#AppVersion}
AppVerName=piikey {#AppVersion}
AppPublisher=TBLgGamin
AppPublisherURL=https://github.com/TBLgGamin/piikey
AppSupportURL=https://github.com/TBLgGamin/piikey/issues
AppUpdatesURL=https://github.com/TBLgGamin/piikey/releases
DefaultDirName={localappdata}\Programs\piikey
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=piikey-{#AppVersion}-setup-x64
SetupIconFile=..\..\app\assets\piikey.ico
UninstallDisplayIcon={app}\piikey.exe
UninstallDisplayName=piikey
LicenseFile=..\..\LICENSE
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\piikey"; Filename: "{app}\piikey.exe"
Name: "{autodesktop}\piikey"; Filename: "{app}\piikey.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\piikey.exe"; Description: "Start piikey"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; In this order: stop the app and its watchdog, give Windows its proxy settings back (a no-op when
; piikey did not change them), then remove the local CA from the user's Root store.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM piikey.exe /F"; Flags: runhidden; RunOnceId: "StopPiikey"
Filename: "{app}\piikey.exe"; Parameters: "--restore-proxy"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "RestoreProxy"
Filename: "{sys}\certutil.exe"; Parameters: "-user -delstore Root ""piikey Guard CA"""; Flags: runhidden; RunOnceId: "RemoveCA"

[Code]
// The vault is needed to restore stand-ins issued earlier, so the data stays unless the user says
// otherwise. A silent uninstall never asks and keeps it.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
  begin
    DataDir := ExpandConstant('{localappdata}\piikey');
    if MsgBox('Also delete your piikey data (vault, settings, downloaded model) in ' + DataDir + '?',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(DataDir, True, True, True);
  end;
end;
