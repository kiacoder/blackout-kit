# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all

datas_ctk, binaries_ctk, hiddenimports_ctk = collect_all('customtkinter')

a = Analysis(
    ['blackout.py'],
    pathex=[],
    binaries=[] + binaries_ctk,
    datas=[('bins/*.dll', 'bins'), ('bins/icon.png', 'bins'), ('assets/*', 'assets')] + datas_ctk,
    hiddenimports=['_overlapped', 'asyncio'] + hiddenimports_ctk,
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
    a.binaries,
    a.datas,
    [],
    name='blackout',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['bins\\icon.png'],
)
