# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller: one windowed executable of the Qt 6 bridge.

Build (from the repository root, in the venv):

    .venv\\Scripts\\pyinstaller.exe --noconfirm --clean gui.spec

The result is var\\dist\\MeshBridge-GUI-<version>-alpha1.exe.  config.json
is not bundled: the executable reads the one next to itself, so the same
file works for the console version (run.bat) and the window.
"""

VERSION = "0.1.0"
BUILD = "a1"
NAME = f"MeshBridge-GUI-{VERSION}-alpha{BUILD[1:]}"

a = Analysis(
    ["gui_boot.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Meshtastic finds its transports by import name at runtime.
        "meshtastic.serial_interface",
        "meshtastic.tcp_interface",
        "meshtastic.ble_interface",
        "serial", "serial.tools.list_ports",
        "bleak",
        "pubsub", "pubsub.pub",
        # PyNaCl uses cffi at import time; PyInstaller finds the module but
        # not its compiled backend, so both are named explicitly.
        "cffi", "_cffi_backend",
        "nacl", "nacl.bindings",
        "lz4.frame",
        "psutil",
        "google.protobuf",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc_data", "test"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    icon=None,
)

# The windowed build.  Two executables follow: the window and the console
# twin used by the self-test (same code, so both need the same inputs).

check = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=NAME + "-selfcheck",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
    icon=None,
)
