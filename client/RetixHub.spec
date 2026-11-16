# -*- mode: python ; coding: utf-8 -*-
# ONEDIR-сборка: dist\RetixHub\RetixHub.exe (+ папка _internal). Собирает build.bat.
# Из onedir собирается установщик (RetixHub.iss) — раздаётся только он.
# UPX выключен: сжатые UPX exe/DLL антивирусы часто считают вирусом.
# Манифест без requireAdministrator: клиент сам перезапускается с правами
# администратора (UAC), а --selftest при сборке работает без UAC.
import re

from PyInstaller.utils.win32.versioninfo import (FixedFileInfo, StringFileInfo, StringStruct, StringTable,
                                                 VarFileInfo, VarStruct, VSVersionInfo)

with open('retixhub_client.py', encoding='utf-8') as f:
    VERSION = re.search(r'^VERSION = "([0-9.]+)"', f.read(), re.M).group(1)
nums = tuple((list(map(int, VERSION.split('.'))) + [0, 0, 0, 0])[:4])

version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=nums, prodvers=nums),
    kids=[
        StringFileInfo([StringTable('041904B0', [
            StringStruct('CompanyName', 'Retix'),
            StringStruct('FileDescription', 'Retix Hub — сеть компании'),
            StringStruct('FileVersion', VERSION),
            StringStruct('InternalName', 'RetixHub'),
            StringStruct('OriginalFilename', 'RetixHub.exe'),
            StringStruct('ProductName', 'Retix Hub'),
            StringStruct('ProductVersion', VERSION),
        ])]),
        VarFileInfo([VarStruct('Translation', [0x0419, 1200])]),
    ],
)

a = Analysis(
    ['retixhub_client.py'],
    pathex=[],
    binaries=[],
    datas=[('app_icon.ico', '.')],
    hiddenimports=['certifi', 'pystray._win32', 'PIL.Image', 'PIL.ImageDraw'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='RetixHub',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app_icon.ico',
    version=version_info,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='RetixHub',
)
