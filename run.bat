@echo off
chcp 65001 >nul
title Meshtastic-Bitchat bridge
cd /d "%~dp0"

set "ARGS=%*"
if "%~1"=="" set "ARGS=--menu"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" bridge.py %ARGS%
) else (
    echo [i] Virtual environment not found, using system Python.
    python bridge.py %ARGS%
)

echo.
echo Bridge stopped. Press any key to close.
pause >nul
