@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Missing virtual environment. Follow BUILD_INSTRUCTIONS.md first.
    exit /b 1
)

".venv\Scripts\python.exe" -m streamlit run app.py
if errorlevel 1 pause
