@echo off
REM ============================================================
REM Rakshak - Start Script
REM ============================================================

echo.
echo ============================================================
echo RAKSHAK - Starting Application
echo ============================================================
echo.

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Check if dependencies are installed
if not exist "node_modules" (
    echo [1/4] Installing dependencies...
    call npm install
)

REM Build frontend first
echo.
echo [2/4] Building frontend...
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] Frontend build failed!
    pause
    exit /b 1
)

REM Start Tauri (builds backend and launches app)
echo.
echo [3/4] Starting Tauri...
call npx tauri build

echo.
echo [DONE] Build complete!
pause
