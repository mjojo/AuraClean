@echo off
setlocal
cd /d "%~dp0"

set "RELEASE_EXE=%~dp0target\release\AuraClean.exe"
set "DEBUG_EXE=%~dp0target\debug\AuraClean.exe"

if exist "%RELEASE_EXE%" (
    start "" "%RELEASE_EXE%"
    exit /b 0
)

if exist "%DEBUG_EXE%" (
    start "" "%DEBUG_EXE%"
    exit /b 0
)

echo [AuraClean by mjojo] Building 1-click native desktop binary for the first time...
cargo build --release -p auraclean-gui
if errorlevel 1 (
    echo [AuraClean] Build failed. Ensure Rust toolchain is installed.
    pause
    exit /b 1
)

start "" "%RELEASE_EXE%"
exit /b 0
