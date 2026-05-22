@echo off
setlocal

set PYTHON_EXE=C:\Users\edwin\AppData\Local\Microsoft\WindowsApps\python3.13.exe
set ISCC_EXE=

if not exist "%PYTHON_EXE%" (
    echo Python executable not found at:
    echo %PYTHON_EXE%
    echo Update PYTHON_EXE in this script to your Python path.
    exit /b 1
)

for /f "delims=" %%I in ('where ISCC.exe 2^>nul') do (
    if not defined ISCC_EXE set ISCC_EXE=%%I
)

if not defined ISCC_EXE if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set ISCC_EXE=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if not defined ISCC_EXE if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set ISCC_EXE=%ProgramFiles%\Inno Setup 6\ISCC.exe
if not defined ISCC_EXE if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set ISCC_EXE=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe
if not defined ISCC_EXE if exist "%ProgramFiles(x86)%\Inno Setup 5\ISCC.exe" set ISCC_EXE=%ProgramFiles(x86)%\Inno Setup 5\ISCC.exe
if not defined ISCC_EXE if exist "%ProgramFiles%\Inno Setup 5\ISCC.exe" set ISCC_EXE=%ProgramFiles%\Inno Setup 5\ISCC.exe

if not defined ISCC_EXE (
    echo Inno Setup 6 compiler not found.
    echo Install it from: https://jrsoftware.org/isinfo.php
    echo Or add ISCC.exe to PATH.
    echo Then run this script again.
    exit /b 1
)

echo Installing or updating build requirements...
"%PYTHON_EXE%" -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
    echo Failed to install requirements.
    exit /b 1
)

echo Building CrashReader executable...
"%PYTHON_EXE%" -m PyInstaller --noconfirm --clean CrashReader.spec
if errorlevel 1 (
    echo EXE build failed.
    exit /b 1
)

echo Building installer package...
"%ISCC_EXE%" installer.iss
if errorlevel 1 (
    echo Installer build failed.
    exit /b 1
)

echo.
echo Installer build complete.
echo Output: installer\CrashReader-Setup.exe

endlocal