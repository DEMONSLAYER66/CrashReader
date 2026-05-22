@echo off
setlocal

set PYTHON_EXE=C:\Users\edwin\AppData\Local\Microsoft\WindowsApps\python3.13.exe

echo Installing or updating build requirements...
"%PYTHON_EXE%" -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
    echo Failed to install requirements.
    exit /b 1
)

echo Building CrashReader.exe...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean --windowed --name CrashReader app.py
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo.
echo Build complete. Output folder:
echo dist\CrashReader\

endlocal
