@echo off
chcp 65001 >nul
title Meshtastic-Bitchat bridge (GUI)
cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" -X utf8 -m gui %*
) else (
    echo [i] Virtual environment not found, using system Python.
    start "" pythonw -X utf8 -m gui %*
)
