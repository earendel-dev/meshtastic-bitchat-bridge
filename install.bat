@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo [1/3] Creating virtual environment...
if not exist ".venv\Scripts\python.exe" (
    py -3 -m venv .venv || goto :error
)

echo [2/3] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt || goto :error

echo [3/3] Preparing config...
if not exist "config.json" (
    if exist "config.example.json" copy /y "config.example.json" "config.json" >nul
)

echo.
echo Done. Start the bridge with run.bat
pause
exit /b 0

:error
echo.
echo Installation failed.
pause
exit /b 1
