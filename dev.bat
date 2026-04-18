@echo off
REM ============================================================
REM Rakshak - Development Start Script
REM ============================================================

echo.
echo ============================================================
echo RAKSHAK - Starting in Development Mode
echo ============================================================
echo.

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Check if dependencies are installed
if not exist "node_modules" (
    echo [1/4] Installing dependencies...
    call npm install
)

REM Start Tauri dev mode (runs frontend + backend)
echo.
echo [2/4] Starting Tauri in development mode...
echo    - Frontend dev server: http://localhost:1420
echo    - Rust backend will be compiled and launched
echo.
call npx tauri dev

pause
