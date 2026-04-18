@echo off
REM ============================================================
REM Rakshak - Development Mode
REM This script starts both frontend dev server and Tauri app
REM ============================================================

echo.
echo ============================================================
echo RAKSHAK - Development Mode
echo ============================================================
echo.

REM Navigate to frontend directory
cd /d "%~dp0frontend"

REM Start Vite dev server in background
echo [1/3] Starting Vite dev server on http://localhost:1420...
start "Rakshak Frontend" cmd /c "npm run dev"

REM Wait for Vite to be ready
echo [2/3] Waiting for frontend server...
timeout /t 5 /nobreak >nul

REM Start Tauri backend (which will connect to the frontend)
echo [3/3] Starting Tauri backend...
cd ..\backend\src-tauri
cargo run

pause
