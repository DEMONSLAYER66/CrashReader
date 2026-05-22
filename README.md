# CrashReader

CrashReader is a desktop GUI tool for monitoring Minecraft modpack crashes and highlighting likely culprit mods.

## What It Does

- Watches a selected modpack folder for new crash files
- Detects likely culprit mods using weighted evidence from crash text
- Shows popup alerts for newly detected crash signatures
- Tracks repeated crashes with signature counts
- Displays likely conflict pairs based on recurring co-occurring mods
- Saves session state and crash history to JSON

## Requirements

- Python 3.10+
- Windows (recommended, due to sound/tray behavior)
- Python packages listed in [requirements.txt](requirements.txt)

Current third-party dependencies:

- pystray
- Pillow
- tomli (auto-used on Python below 3.11 for TOML parsing/validation)

## Quick Start

You do not need VS Code to use CrashReader.

1. Open this project folder in File Explorer.
2. Double-click `start_sleepcast.bat`.

That is all you need.

If you prefer terminal commands, start the launcher with:

```powershell
start_sleepcast.bat
```

This runs:

```powershell
python app.py --auto-bootstrap
```

If required packages are missing, CrashReader will prompt to install them automatically.

## Alternative Run Modes

- Normal start (includes startup requirement check):

```powershell
python app.py
```

- GUI only (skip startup prompts/checks):

```powershell
python app.py --gui-only
```

- Auto-bootstrap mode (used by launcher batch file):

```powershell
python app.py --auto-bootstrap
```

## Crash Sources Monitored

After selecting a modpack folder, CrashReader monitors:

- `<modpack>/crash-reports/crash-*.txt`
- `<modpack>/.minecraft/crash-reports/crash-*.txt`
- `<modpack>/hs_err_pid*.log`

## Detection Logic Summary

CrashReader scores potential culprit mods using signals such as:

- `-- MOD <modid> --` sections
- `Suspected Mods:` lines
- `Mod File:` entries
- `Caused by:` chains
- Name matches against installed `mods/*.jar` files

It then ranks candidates and reports:

- Top likely mods
- Confidence (`Low`, `Medium`, `High`)
- Severity (`Minor`, `Major`, `Critical`)
- Loader profile (`Forge`, `NeoForge`, `Fabric`, `Quilt`, `Unknown`)

## UI Highlights

- `Crash Monitor` tab:
  - Select modpack folder and save folder
  - Toggle fullscreen (`F11`, `Esc` to exit)
  - Enable/disable alert sound
  - Optional minimize-to-tray mode (requires `pystray` + `Pillow`)
  - Crash table with signature count and loader info
  - Detail panel with evidence per suspected mod
  - Top conflict pairs panel

- `Live Logs` tab:
  - Dedicated live ERROR/FATAL log event table
  - Detail panel for selected log events

- `Mods` tab:
  - Lists detected mod jars and best-effort versions

- `Config` tab:
  - Browse and filter modpack config files
  - Edit config text directly
  - Select detected key/value rows and apply value updates
  - Apply updates writes changes to the real modpack config file
  - Create and restore an original config backup

- `Diagnostics` tab:
  - Watcher state, queue sizes, last-seen crash/log file, last popup time

- `Settings` tab:
  - Popup on/off, repeat-popup behavior, cooldown
  - Test popup / test sound
  - Clear runtime lists

## Install Command

If you want to install dependencies manually:

```powershell
python -m pip install -r requirements.txt
```

## Build Windows EXE

CrashReader can be bundled into an executable with PyInstaller.

Quick build:

```powershell
build_exe.bat
```

Manual build command:

```powershell
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --clean --windowed --name CrashReader app.py
```

Build output:

- `dist/CrashReader/CrashReader.exe`

## Build Windows Installer

You can create a standard Windows installer (`.exe`) without changing anything inside the `app` folder.

Prerequisite:

- Inno Setup 6 (includes `ISCC.exe` compiler):
  - https://jrsoftware.org/isinfo.php

One-step build (EXE + installer):

```powershell
build_installer.bat
```

What this does:

- Installs/updates Python requirements and `pyinstaller`
- Builds `dist/CrashReader/CrashReader.exe`
- Compiles `installer.iss` with Inno Setup

Installer output:

- `installer/CrashReader-Setup.exe`

## Publish Online (GitHub Releases)

This repo now includes an automated release workflow at [`.github/workflows/release.yml`](.github/workflows/release.yml).

When you push a git tag like `v1.0.0`, GitHub Actions will:

- Build the app with PyInstaller
- Build the installer with Inno Setup
- Create/update a GitHub Release for that tag
- Upload installer asset named `CrashReader-Setup-v1.0.0.exe`

Commands:

```powershell
git add .
git commit -m "Prepare release"
git push origin main
git tag v1.0.0
git push origin v1.0.0
```

After the workflow finishes, users can download from:

- `https://github.com/<your-username>/<your-repo>/releases`

Notes:

- In executable mode, default save data is written to `%LOCALAPPDATA%/CrashReader/save`.
- The runtime dependency bootstrap flow is skipped in executable mode because dependencies are already bundled.

## Saved Data

By default, files are stored in [save](save):

- [save/session_state.json](save/session_state.json): selected folders, UI settings, toggles
- [save/crash_history.json](save/crash_history.json): persisted crash events/history
- [save/config backup](save/config%20backup): original config backup folder (used by Config tab restore)

You can change the save folder in the UI (`Choose Save Folder`).

When you switch to a different modpack folder, CrashReader refreshes data for that modpack and recreates the config backup context for the newly selected pack.

## Notes

- Best results come from selecting the real modpack root folder (the one containing `mods` and/or crash-report locations).
- On startup, CrashReader runs a health check and may warn when expected folders/files are missing.
