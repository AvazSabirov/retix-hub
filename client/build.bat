@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
REM Сборка Retix Hub. Собирать на Windows 10/11 x64: Python 3.10+ 64-бит (в PATH), Python 3.11 64-бит, Inno Setup 6.3+.
REM Один установщик для Windows 8.1, 10 и 11: внутри две сборки программы, на ПК ставится нужная.
REM   1. dist\RetixHub\RetixHub.exe        - программа для Windows 10/11 (Python из PATH)
REM      dist81\RetixHub\RetixHub.exe      - программа для Windows 8.1: Python 3.11 и cryptography 42.0.5
REM                                          (requirements-win81.txt) - более новые на Windows 8.1 не работают
REM   2. самопроверка обоих exe            - модули, Tcl/Tk, SSL, иконка
REM   3. client\wireguard\*.msi            - официальный WireGuard для Windows 10/11 (скачивается один раз)
REM      client\wireguard81\*.msi          - WireGuard 0.5.3: новые версии Windows 8.1 не поддерживают
REM      client\rustdesk\rustdesk-*.exe     - официальный RustDesk для удалённого управления (тоже один раз)
REM   4. dist\RetixHub_Setup_<версия>.exe  - установщик: раздаётся пользователям и
REM                                          кладётся на сервер в /root/hub/data/downloads/
REM Python 3.11 для сборки под Windows 8.1: путь в переменной PY81 (set PY81=C:\Python311\python.exe),
REM иначе берётся py -3.11. Он ставится в отдельное окружение .venv81 и основной Python не трогает.
REM Версия берётся из VERSION в retixhub_client.py.

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 goto :fail

for /f "usebackq delims=" %%v in (`python -c "import retixhub_client as c; print(c.VERSION)"`) do set APPVER=%%v
if "%APPVER%"=="" (
    echo ОШИБКА: не удалось прочитать VERSION из retixhub_client.py
    goto :fail
)
echo Версия: %APPVER%

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist build81 rmdir /s /q build81
if exist dist81 rmdir /s /q dist81
python -m PyInstaller --noconfirm --clean RetixHub.spec
if errorlevel 1 goto :fail
call :selftest dist\RetixHub
if errorlevel 1 goto :fail

REM Сборка для Windows 8.1: Python 3.11 в отдельном окружении .venv81
if not defined PY81 for /f "delims=" %%p in ('py -3.11 -c "import sys; print(sys.executable)" 2^>nul') do set "PY81=%%p"
if not defined PY81 (
    echo ОШИБКА: для сборки под Windows 8.1 нужен Python 3.11 64-бит: https://www.python.org/downloads/release/python-3119/
    echo Если он стоит не через py, укажите путь: set PY81=C:\Python311\python.exe
    goto :fail
)
"%PY81%" -c "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 11) and struct.calcsize('P') == 8 else 1)"
if errorlevel 1 (
    echo ОШИБКА: PY81 указывает не на Python 3.11 64-бит
    goto :fail
)
if not exist .venv81\Scripts\python.exe "%PY81%" -m venv .venv81
if not exist .venv81\Scripts\python.exe goto :fail
.venv81\Scripts\python -m pip install --upgrade pip
.venv81\Scripts\python -m pip install -r requirements.txt -c requirements-win81.txt
if errorlevel 1 goto :fail
.venv81\Scripts\python -m PyInstaller --noconfirm --clean --distpath dist81 --workpath build81 RetixHub.spec
if errorlevel 1 goto :fail
call :selftest dist81\RetixHub
if errorlevel 1 goto :fail

REM WireGuard для установщика: свежий (Windows 10/11) и 0.5.3 (Windows 8.1)
powershell -NoProfile -ExecutionPolicy Bypass -File get_wireguard.ps1
if errorlevel 1 goto :fail

REM RustDesk для удалённого управления (официальный, без изменений)
powershell -NoProfile -ExecutionPolicy Bypass -File get_rustdesk.ps1
if errorlevel 1 goto :fail

REM Inno Setup: из PATH или из стандартных папок
set "ISCC="
for /f "delims=" %%i in ('where ISCC.exe 2^>nul') do if not defined ISCC set "ISCC=%%i"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC (
    echo ОШИБКА: не найден Inno Setup 6 ^(ISCC.exe^). Установите: https://jrsoftware.org/isdl.php
    goto :fail
)

"%ISCC%" /Qp /DAppVer=%APPVER% RetixHub.iss
if errorlevel 1 goto :fail

echo.
echo Готово: dist\RetixHub_Setup_%APPVER%.exe (Windows 8.1, 10, 11 x64)
echo На сервер: положите его в /root/hub/data/downloads/ на сервере - сайт отдаст самый новый.
if not defined CI pause
exit /b 0

REM Самопроверка собранного exe: %1 - папка сборки (dist\RetixHub или dist81\RetixHub)
:selftest
echo.
start "" /wait %1\RetixHub.exe --selftest
set SELFTEST_RC=%errorlevel%
if not exist %1\retixhub_selftest.txt (
    echo НЕТ ОТЧЁТА САМОПРОВЕРКИ: %1\RetixHub.exe не запустился - проверьте антивирус.
    exit /b 1
)
type %1\retixhub_selftest.txt
if not "%SELFTEST_RC%"=="0" (
    echo САМОПРОВЕРКА НЕ ПРОЙДЕНА - см. %1\retixhub_selftest.txt
    exit /b 1
)
del %1\retixhub_selftest.txt >nul 2>&1
exit /b 0

:fail
echo.
echo ОШИБКА сборки.
if not defined CI pause
exit /b 1
