@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
REM Сборка Retix Hub (Windows 10/11 x64, Python 3.10+ 64-бит, Inno Setup 6.3+)
REM   1. dist\RetixHub\RetixHub.exe        - программа (onedir, PyInstaller)
REM   2. самопроверка собранного exe       - модули, Tcl/Tk, SSL, иконка
REM   3. client\wireguard\*.msi            - официальный WireGuard (скачивается один раз)
REM   4. dist\RetixHub_Setup_<версия>.exe  - установщик: раздаётся пользователям и
REM                                          кладётся на сервер в /root/hub/data/downloads/
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
python -m PyInstaller --noconfirm --clean RetixHub.spec
if errorlevel 1 goto :fail

REM Самопроверка собранного exe
echo.
start "" /wait dist\RetixHub\RetixHub.exe --selftest
set SELFTEST_RC=%errorlevel%
if exist dist\RetixHub\retixhub_selftest.txt (
    type dist\RetixHub\retixhub_selftest.txt
) else (
    echo НЕТ ОТЧЁТА САМОПРОВЕРКИ: RetixHub.exe не запустился - проверьте антивирус.
    goto :fail
)
if not "%SELFTEST_RC%"=="0" (
    echo САМОПРОВЕРКА НЕ ПРОЙДЕНА - см. dist\RetixHub\retixhub_selftest.txt
    goto :fail
)
del dist\RetixHub\retixhub_selftest.txt >nul 2>&1

REM WireGuard для установщика
powershell -NoProfile -ExecutionPolicy Bypass -File get_wireguard.ps1
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
echo Готово: dist\RetixHub_Setup_%APPVER%.exe
echo На сервер: положите его в /root/hub/data/downloads/ на сервере - сайт отдаст самый новый.
if not defined CI pause
exit /b 0

:fail
echo.
echo ОШИБКА сборки.
if not defined CI pause
exit /b 1
