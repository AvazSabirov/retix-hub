; ============================================================================
;  Retix Hub — установщик (Inno Setup 6.3 или новее)
;
;  Собирает build.bat после сборки PyInstaller:
;      ISCC.exe /DAppVer=1.0.0 RetixHub.iss
;  Результат: dist\RetixHub_Setup_<версия>.exe
;
;  Как работает (первая установка и обновление одинаково):
;   - никаких страниц и вопросов: окно UAC Windows и полоса прогресса;
;   - перед установкой клиент Retix Hub закрывается. Его можно завершать
;     сразу (taskkill /F): VPN держит служба WireGuard, а не окно клиента,
;     связь при обновлении не рвётся;
;   - старые файлы программы (_internal) удаляются, копируется новая сборка;
;   - WireGuard ставится из вложенного MSI, если его ещё нет;
;   - ярлыки: рабочий стол и меню «Пуск». Автозапуск создаёт сам клиент
;     (задача Планировщика «RetixHub» с правами администратора — без UAC
;     при каждом входе в Windows);
;   - после установки клиент запускается (кроме /SILENT и /VERYSILENT);
;   - данные в %ProgramData%\RetixHub (ключ, вход) и журнал {app}\logs установщик
;     при обновлении не трогает (журнал удаляется вместе с программой);
;   - при удалении: туннель, правила firewall и автозапуск
;     снимаются (RetixHub.exe --uninstall). WireGuard остаётся;
;   - установка более старой версии поверх новой запрещена.
;
;  Тихая установка на много ПК:  RetixHub_Setup_<версия>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;
;  AppGuid НИКОГДА НЕ МЕНЯТЬ: по нему установщик находит прошлую установку.
;  Файл в UTF-8 с BOM — так Inno Setup правильно читает русский текст.
; ============================================================================

#define AppName  "Retix Hub"
#define AppExe   "RetixHub.exe"
#define AppGuid  "{AB5A7EE4-CA22-47B0-8BE1-A5707FE2F67D}"
#define DistDir  "dist\RetixHub"

#ifndef AppVer
  #define AppVer GetVersionNumbersString(AddBackslash(AddBackslash(SourcePath) + DistDir) + AppExe)
#endif

[Setup]
AppId={{#AppGuid}
AppName={#AppName}
AppVersion={#AppVer}
AppVerName={#AppName} {#AppVer}
AppPublisher=Retix
AppPublisherURL=https://hub.retix.uz
AppSupportURL=https://hub.retix.uz
VersionInfoVersion={#AppVer}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} — установщик

DefaultDirName={autopf}\RetixHub
UsePreviousAppDir=yes
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; WireGuard в установщике — 64-битный (amd64)
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

DisableWelcomePage=yes
DisableDirPage=yes
DisableReadyPage=yes
DisableFinishedPage=yes

CloseApplications=no
RestartApplications=no
SetupMutex=RetixHubSetupMutex

SetupIconFile=app_icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
OutputDir=dist
OutputBaseFilename=RetixHub_Setup_{#AppVer}
Compression=lzma2/max
SolidCompression=yes

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[InstallDelete]
; библиотеки прошлой версии — чтобы не смешались с новыми
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#DistDir}\*"; DestDir: "{app}"; Excludes: "retixhub_selftest.txt"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "client_config.json"; DestDir: "{app}"; Flags: ignoreversion
; клиент сам поставит WireGuard из MSI рядом с exe, если его удалят
Source: "wireguard\wireguard-amd64-*.msi"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"

[Run]
; установщик уже с правами администратора — клиент стартует без второго окна UAC
Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Flags: nowait skipifsilent

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "--uninstall"; WorkingDir: "{app}"; Flags: waituntilterminated runhidden; RunOnceId: "RetixHubCleanup"

[UninstallDelete]
Type: files; Name: "{app}\retixhub_selftest.txt"
Type: filesandordirs; Name: "{app}\logs"

[Code]
const
  KillWaitSec = 15;
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppGuid}_is1';

{ Запущен ли RetixHub.exe (любой сеанс Windows) }
function IsClientRunning: Boolean;
var
  OutFile: String;
  Output: AnsiString;
  RC: Integer;
begin
  Result := False;
  OutFile := AddBackslash(GetTempDir) + 'retixhub_tasklist.txt';
  DeleteFile(OutFile);
  if Exec(ExpandConstant('{cmd}'),
          '/C tasklist /NH /FI "IMAGENAME eq {#AppExe}" > "' + OutFile + '"',
          '', SW_HIDE, ewWaitUntilTerminated, RC) then
    if LoadStringFromFile(OutFile, Output) then
      Result := Pos(Lowercase('{#AppExe}'), Lowercase(String(Output))) > 0;
  DeleteFile(OutFile);
end;

{ Закрыть клиент. Крестик окна у клиента только сворачивает, поэтому сразу
  taskkill /F: туннель — служба WireGuard, она продолжает работать.
  True — клиента нет. }
function CloseClient: Boolean;
var
  RC, I: Integer;
begin
  Result := not IsClientRunning;
  if Result then
    Exit;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#AppExe}', '', SW_HIDE,
       ewWaitUntilTerminated, RC);
  for I := 1 to KillWaitSec do
  begin
    if not IsClientRunning then
    begin
      Log('Retix Hub закрыт');
      Result := True;
      Exit;
    end;
    Sleep(1000);
  end;
  Log('ОШИБКА: RetixHub.exe не завершился');
end;

function IsDowngrade(var OldVer: String): Boolean;
var
  OldV, NewV: Int64;
begin
  Result := False;
  if RegQueryStringValue(HKA, UninstKey, 'DisplayVersion', OldVer) then
    if StrToVersion(OldVer, OldV) and StrToVersion('{#AppVer}', NewV) then
      Result := ComparePackedVersion(NewV, OldV) < 0;
end;

function InitializeSetup: Boolean;
var
  OldVer: String;
begin
  Result := False;
  if IsDowngrade(OldVer) then
  begin
    SuppressibleMsgBox('Установлена более новая версия Retix Hub (' + OldVer + ').' + #13#10 +
      'Установка версии {#AppVer} поверх неё отменена.', mbError, MB_OK, IDOK);
    Exit;
  end;
  Result := True;
end;

{ Страницу «Готово к установке» Inno показывает, если она первая, — жмём «Установить» сами }
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpReady then
    PostMessage(WizardForm.NextButton.Handle, $00F5 { BM_CLICK }, 0, 0);
end;

{ Перед копированием файлов: клиента быть не должно }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not CloseClient then
    Result := 'Не удалось закрыть Retix Hub (RetixHub.exe). Закройте его и запустите установку снова.';
end;

function WireGuardInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\WireGuard\wireguard.exe'));
end;

{ После копирования: поставить WireGuard, если его нет }
procedure InstallWireGuard;
var
  FindRec: TFindRec;
  Msi: String;
  RC: Integer;
begin
  if WireGuardInstalled then
  begin
    Log('WireGuard уже установлен');
    Exit;
  end;
  Msi := '';
  if FindFirst(ExpandConstant('{app}\wireguard-amd64-*.msi'), FindRec) then
  try
    Msi := ExpandConstant('{app}\') + FindRec.Name;
  finally
    FindClose(FindRec);
  end;
  if Msi = '' then
  begin
    Log('ОШИБКА: MSI WireGuard не найден');
    Exit;
  end;
  WizardForm.StatusLabel.Caption := 'Установка WireGuard…';
  Log('Ставлю ' + Msi);
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), '/i "' + Msi + '" /qn /norestart DO_NOT_LAUNCH=1',
              '', SW_HIDE, ewWaitUntilTerminated, RC) or not WireGuardInstalled then
  begin
    Log('ОШИБКА: WireGuard не установился, код ' + IntToStr(RC));
    SuppressibleMsgBox('WireGuard не установился (код ' + IntToStr(RC) + ').' + #13#10 +
      'Retix Hub попробует поставить его сам при запуске.', mbError, MB_OK, IDOK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    InstallWireGuard;
end;

function InitializeUninstall: Boolean;
begin
  Result := CloseClient;
  if not Result then
    SuppressibleMsgBox('Retix Hub не закрылся. Закройте программу и запустите удаление снова.',
      mbError, MB_OK, IDOK);
end;
