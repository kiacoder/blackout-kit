# -*- mode: python ; coding: utf-8 -*-

import glob
import os

from PyInstaller.utils.hooks import collect_all, collect_submodules

datas_ctk, binaries_ctk, hiddenimports_ctk = collect_all("customtkinter")
datas_typer, binaries_typer, hiddenimports_typer = collect_all("typer")
hiddenimports_blackout = collect_submodules("blackoutkit")

# Native DLLs are never committed (see bins/.gitkeep and .gitignore), so bundle
# whichever ones are present on the build machine. A glob with no match aborts
# PyInstaller, which broke clean CI checkouts.
bundled_dlls = [(path, "bins") for path in sorted(glob.glob(os.path.join(SPECPATH, "bins", "*.dll")))]

a = Analysis(
    ['blackout.py'],
    pathex=[],
    binaries=[] + binaries_ctk + binaries_typer,
    datas=[
        ("bins/icon.png", "bins"),
        ("assets/*", "assets"),
        ("data/cloudflare_ips.txt", "data"),
        ("data/fake_snis.txt", "data"),
        ("data/gas_ids.txt", "data"),
        # User configs are mutable and may contain credentials; never bundle them.
        ("blackoutkit/resources/data/*.txt", "blackoutkit/resources/data"),
        ("blackoutkit/resources/assets/*", "blackoutkit/resources/assets"),
    ] + bundled_dlls + datas_ctk + datas_typer,
    hiddenimports=["_overlapped", "asyncio"] + hiddenimports_ctk + hiddenimports_typer + hiddenimports_blackout,
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
