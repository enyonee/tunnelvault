@echo off
rem tunnelvault runner for Windows - activates venv and runs the script
setlocal

set "SCRIPT_DIR=%~dp0"

if not exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
    echo venv not found. Run: .\setup.ps1 1>&2
    exit /b 1
)

"%SCRIPT_DIR%.venv\Scripts\python.exe" "%SCRIPT_DIR%tunnelvault.py" %*
