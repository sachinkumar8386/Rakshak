@echo off
REM ============================================================
REM Rakshak - Production Build & Run
REM This script builds the app and runs it
REM ============================================================

echo.
echo ============================================================
echo RAKSHAK - Production Build
echo ============================================================
echo.

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Check if dependencies are installed
if not exist "node_modules" (
    echo [1/5] Installing frontend dependencies...
    call npm install
)

REM Build frontend
echo.
echo [2/5] Building frontend...
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] Frontend build failed!
    pause
    exit /b 1
)

REM Build Tauri backend (release mode)
echo.
echo [3/5] Building Tauri backend...
cd ..\backend\src-tauri
if not exist "target\release\tauri-app.exe" (
    echo    Building release binary...
    cargo build --release
)

REM Run the app
echo.
echo [4/5] Launching Rakshak...
echo.
cargo run --release

echo.
echo [5/5] Application closed.
pause
