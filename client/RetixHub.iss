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
;   - Windows 8.1, 10 и 11 (x64) — одним установщиком. Внутри две сборки программы и два WireGuard:
;     Windows 10/11 — dist\RetixHub и свежий WireGuard; Windows 8.1 — dist81\RetixHub (Python 3.11,
;     cryptography 42.0.5) и WireGuard 0.5.3: более новые на 8.1 не работают. Ставится только нужное,
;     обновления — тем же установщиком для всех. На 8.1 нужен Universal C Runtime (KB2999226);
;   - WireGuard ставится из вложенного MSI, если его ещё нет;
;   - официальный RustDesk (rustdesk-<версия>-x86_64.exe) кладётся рядом с программой — его ставит
;     и настраивает клиент, когда в кабинете компании включено удалённое управление;
;   - ярлыки: рабочий стол и меню «Пуск»;
;   - автозапуск сразу при установке: задача Планировщика «RetixHub» с правами
;     администратора (без UAC при каждом входе в Windows), окно — в трее;
;   - после установки клиент запускается (кроме /SILENT и /VERYSILENT);
;   - автообновление: версию публикует суперадмин (/admin/updates), клиент проверяет подпись
;     и сам запускает установщик с /VERYSILENT /AUTOUPDATE=1 — после установки клиент
;     запускается снова (в трее);
;   - данные в %ProgramData%\RetixHub (ключ, вход) и журнал {app}\logs установщик
;     при обновлении не трогает (журнал удаляется вместе с программой);
;   - при удалении: туннель, правила firewall и автозапуск
;     снимаются (RetixHub.exe --uninstall). WireGuard остаётся; RustDesk удаляется,
;     если его поставил Retix Hub;
;   - установка более старой версии поверх новой запрещена;
;   - перед заменой файлов папка _internal должна быть свободна: её библиотеки не держит ни один процесс.
;     Иначе часть файлов осталась бы старой, и программа не запустилась бы («ошибка библиотеки Python»).
;     Не освободилась за 30 с — установка отменяется, прежняя версия остаётся рабочей;
;   - журнал установки — всегда; копия — {app}\logs\setup.log (её присылает кнопка «Журнал» в кабинете).
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
#define Dist81Dir "dist81\RetixHub"

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
; Windows 8.1 и новее: для 8.1 — своя сборка программы и WireGuard (IsWin81)
MinVersion=6.3.9600

DisableWelcomePage=yes
DisableDirPage=yes
DisableReadyPage=yes
DisableFinishedPage=yes

CloseApplications=no
RestartApplications=no
SetupMutex=RetixHubSetupMutex
; журнал установки (в %TEMP%), в конце копируется в {app}\logs\setup.log
SetupLogging=yes

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
; прежняя версия RustDesk — клиент берёт самую новую, но старые файлы ни к чему
Type: files; Name: "{app}\rustdesk-*.exe"
; MSI WireGuard — тот, что подходит этой Windows (после обновления 8.1 до 10 — уже свежий)
Type: files; Name: "{app}\wireguard-amd64-*.msi"

[Files]
; программа: сборка для Windows 10/11 или для Windows 8.1
Source: "{#DistDir}\*"; DestDir: "{app}"; Excludes: "retixhub_selftest.txt"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not IsWin81
Source: "{#Dist81Dir}\*"; DestDir: "{app}"; Excludes: "retixhub_selftest.txt"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: IsWin81
Source: "client_config.json"; DestDir: "{app}"; Flags: ignoreversion
; клиент сам поставит WireGuard из MSI рядом с exe, если его удалят
Source: "wireguard\wireguard-amd64-*.msi"; DestDir: "{app}"; Flags: ignoreversion; Check: not IsWin81
Source: "wireguard81\wireguard-amd64-*.msi"; DestDir: "{app}"; Flags: ignoreversion; Check: IsWin81
; удалённое управление: официальный RustDesk, ставит клиент (rustdesk.exe --silent-install), когда его включат
Source: "rustdesk\rustdesk-*-x86_64.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"

[Run]
; автозапуск при входе в Windows — сразу при установке: задача Планировщика с наивысшими правами
; (программе нужны права администратора, а задача запускает её без окна UAC), окно — свёрнутым в трей
Filename: "{sys}\schtasks.exe"; Parameters: "/Create /F /TN ""RetixHub"" /SC ONLOGON /RL HIGHEST /TR ""\""{app}\{#AppExe}\"" --minimized"""; Flags: runhidden waituntilterminated; StatusMsg: "Автозапуск при входе в Windows…"
; установщик уже с правами администратора — клиент стартует без второго окна UAC
Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Flags: nowait skipifsilent
; автообновление (тихая установка из клиента): запустить новую версию, окно — в трее
Filename: "{app}\{#AppExe}"; Parameters: "--minimized"; WorkingDir: "{app}"; Flags: nowait; Check: IsAutoUpdate

[UninstallRun]
Filename: "{app}\{#AppExe}"; Parameters: "--uninstall"; WorkingDir: "{app}"; Flags: waituntilterminated runhidden; RunOnceId: "RetixHubCleanup"

[UninstallDelete]
Type: files; Name: "{app}\retixhub_selftest.txt"
Type: filesandordirs; Name: "{app}\_internal.old"
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
  Без /T: запущенные из клиента Radmin Viewer, RDP и ping не закрываются.
  True — клиента нет. }
function CloseClient: Boolean;
var
  RC, I: Integer;
begin
  Result := not IsClientRunning;
  if Result then
    Exit;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE,
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

{ Windows 8.1 (6.3): своя сборка программы и WireGuard 0.5.3. Windows 10/11 — 10.0 }
function IsWin81: Boolean;
begin
  Result := GetWindowsVersion < $0A000000;
end;

{ Установщик запущен автообновлением клиента: /AUTOUPDATE=1 }
function IsAutoUpdate: Boolean;
begin
  Result := ExpandConstant('{param:AUTOUPDATE|0}') = '1';
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
  { Python 3.11 программы для 8.1 работает на Universal C Runtime: на 8.1 он приходит обновлением Windows }
  if IsWin81 and not FileExists(ExpandConstant('{sys}\ucrtbase.dll')) then
  begin
    SuppressibleMsgBox('Для Retix Hub на Windows 8.1 нужно обновление Windows KB2999226' + #13#10 +
      '(Universal C Runtime). Установите обновления через Центр обновления Windows' + #13#10 +
      'или KB2999226 с сайта Microsoft и запустите установку снова.', mbError, MB_OK, IDOK);
    Exit;
  end;
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

{ В журнал установки: какие процессы держат библиотеку Python программы }
procedure LogBusyProcesses;
var
  OutFile: String;
  Output: AnsiString;
  RC: Integer;
begin
  OutFile := AddBackslash(GetTempDir) + 'retixhub_busy.txt';
  DeleteFile(OutFile);
  if Exec(ExpandConstant('{cmd}'), '/C tasklist /M python3*.dll > "' + OutFile + '"', '', SW_HIDE,
          ewWaitUntilTerminated, RC) then
    if LoadStringFromFile(OutFile, Output) then
      Log('Процессы с библиотекой Python:' + #13#10 + String(Output));
  DeleteFile(OutFile);
end;

{ Папка _internal (библиотеки программы) свободна: её удаётся переименовать — значит, ни один процесс не держит
  её файлы. Занятую папку установщик заменил бы лишь частично: старые и новые библиотеки вперемешку, и программа
  не запускается («ошибка библиотеки Python»). Ждём до 30 с, добивая RetixHub.exe. True — папки больше нет. }
function FreeInternalDir: Boolean;
var
  Dir, Old: String;
  I, RC: Integer;
begin
  Dir := ExpandConstant('{app}\_internal');
  Old := Dir + '.old';
  if DirExists(Old) then
    DelTree(Old, True, True, True);
  Result := not DirExists(Dir);
  if Result then
    Exit;
  for I := 1 to 30 do
  begin
    if RenameFile(Dir, Old) then
    begin
      Log('_internal свободна (попытка ' + IntToStr(I) + ')');
      DelTree(Old, True, True, True);   { что не удалилось — удалит следующая установка }
      Result := True;
      Exit;
    end;
    if I = 1 then
    begin
      Log('_internal занята — ждём');
      LogBusyProcesses;
    end;
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, RC);
    Sleep(1000);
  end;
  LogBusyProcesses;
  Log('ОШИБКА: _internal так и не освободилась — установка отменена, прежняя версия не тронута');
end;

{ Перед копированием файлов: клиента быть не должно, и его библиотеки никто не держит }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not CloseClient then
    Result := 'Не удалось закрыть Retix Hub (RetixHub.exe). Закройте его и запустите установку снова.'
  else if not FreeInternalDir then
    Result := 'Файлы Retix Hub заняты другим процессом. Перезагрузите компьютер и запустите установку снова.';
end;

{ В конце (и при отмене): копия журнала установки рядом с журналом программы }
procedure DeinitializeSetup;
var
  Src, Dest: String;
begin
  try
    Src := ExpandConstant('{log}');
    Dest := ExpandConstant('{app}\logs');
    if (Src <> '') and DirExists(ExpandConstant('{app}')) then
    begin
      ForceDirectories(Dest);
      FileCopy(Src, Dest + '\setup.log', False);
    end;
  except
    // папка программы ещё не известна (установку отменили в самом начале) — копировать нечего
  end;
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
