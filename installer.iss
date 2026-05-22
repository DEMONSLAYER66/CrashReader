[Setup]
AppId={{A3B0F709-1DA9-4ED2-93D4-E2BFE1B8C3E8}
AppName=CrashReader
AppVersion=1.0.0
AppPublisher=CrashReader
DefaultDirName={autopf}\CrashReader
DefaultGroupName=CrashReader
DisableProgramGroupPage=yes
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir=installer
OutputBaseFilename=CrashReader-Setup
UninstallDisplayIcon={app}\CrashReader.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "dist\CrashReader\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\CrashReader"; Filename: "{app}\CrashReader.exe"
Name: "{autodesktop}\CrashReader"; Filename: "{app}\CrashReader.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\CrashReader.exe"; Description: "Launch CrashReader"; Flags: nowait postinstall skipifsilent