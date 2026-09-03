#define MyAppName "Rune"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Aayush Patel"
#define MyAppURL "https://github.com/theaayushpatel/rune"
#define MyAppExeName "rune-desktop.exe"

[Setup]
AppId={{D37F249F-E138-4C89-BE32-84191D1236EF}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
ChangesEnvironment=yes
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=.
OutputBaseFilename=rune-windows-x86_64-installer
SetupIconFile=assets\rune.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add Rune to system PATH (so 'rune' CLI command works anywhere in terminal)"; GroupDescription: "System Integration"

[Files]
Source: "staging\rune-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\rune.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\rune.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\rune.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\rune.ico"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
