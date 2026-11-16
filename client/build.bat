@echo off
chcp 65001 >nul
rem Сборка RetixHub.exe (запускать на Windows, Python 3.11+)
python -m pip install -r requirements.txt
pyinstaller --onefile --noconsole --uac-admin --name RetixHub retixhub_client.py
copy /Y client_config.json dist\
echo.
echo Готово: dist\RetixHub.exe + dist\client_config.json
echo Положите рядом wireguard-amd64-*.msi — клиент сам установит WireGuard, если его нет.
pause
