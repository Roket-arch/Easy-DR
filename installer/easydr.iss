; Installateur Easy DR — compile avec Inno Setup 6 :  ISCC installer\easydr.iss
#define AppName "Easy DR"
#define AppVersion "1.0.0"

[Setup]
AppId={{7B1F2C84-5E0A-4D6B-9C21-EA5D00D12A01}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Easy DR
DefaultDirName={autopf}\Easy DR
DefaultGroupName=Easy DR
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=EasyDR-Setup
SetupIconFile=..\assets\easydr.ico
UninstallDisplayIcon={app}\EasyDR.exe
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
; dossier de données partagé entre le service (admin) et l'interface (utilisateur)
Name: "{commonappdata}\EasyDR"; Permissions: users-modify

[Files]
Source: "..\dist\EasyDR\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "register_task.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Easy DR"; Filename: "{app}\EasyDR.exe"
Name: "{autodesktop}\Easy DR"; Filename: "{app}\EasyDR.exe"

[Run]
; 1) tâche planifiée = démarrage automatique en arrière-plan  2) lancement immédiat  3) ouverture de l'interface
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\register_task.ps1"" -ExePath ""{app}\EasyDR.exe"""; Flags: runhidden waituntilterminated; StatusMsg: "Configuration du démarrage automatique..."
Filename: "schtasks.exe"; Parameters: "/Run /TN EasyDR"; Flags: runhidden waituntilterminated
Filename: "{app}\EasyDR.exe"; Description: "Ouvrir Easy DR"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM EasyDR.exe"; Flags: runhidden; RunOnceId: "KillEasyDR"
Filename: "schtasks.exe"; Parameters: "/Delete /TN EasyDR /F"; Flags: runhidden; RunOnceId: "DelTask"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  { mise à jour : on arrête l'ancienne version avant de remplacer les fichiers }
  Exec('taskkill.exe', '/F /IM EasyDR.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := '';
end;
