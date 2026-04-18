@echo off
REM ============================================================
REM Rakshak Ransomware Detection Test Runner
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo RAKSHAK RANSOMWARE DETECTION TEST RUNNER
echo ============================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Python not found - Python-based tests will be skipped
    echo.
)

REM Get script directory
set "SCRIPT_DIR=%~dp0"
set "TEST_DIR=%SCRIPT_DIR%test_scripts"

echo [1] Starting Rakshak Test Suite
echo.
echo What would you like to test?
echo.
echo   [1] Quick Connection Test
echo       - Verifies backend is responding
echo       - Takes 5 seconds
echo.
echo   [2] Entropy Spike Detection Test
echo       - Creates files with high-entropy (random) data
echo       - Tests Rakshak's entropy-based detection
echo       - Takes ~10 seconds
echo.
echo   [3] Velocity Detection Test
echo       - Rapidly modifies many files
echo       - Tests Rakshak's rate-based detection
echo       - Takes ~10 seconds
echo.
echo   [4] Extension Change Detection Test
echo       - Renames files with suspicious extensions
echo       - Tests Rakshak's extension monitoring
echo       - Takes ~10 seconds
echo.
echo   [5] Combined Multi-Vector Attack
echo       - Runs all attack types in sequence
echo       - Tests full detection pipeline
echo       - Takes ~30 seconds
echo.
echo   [6] UI-Based Threat Simulation
echo       - Instructions for using the Connection Test page
echo       - Simulates CRITICAL/HIGH/MEDIUM threats
echo       - Takes a few seconds
echo.
echo   [7] Full Test Suite (Recommended)
echo       - Connection test + all attack simulations
echo       - Comprehensive validation
echo       - Takes ~60 seconds
echo.
echo   [Q] Quit
echo.

set /p choice="Enter choice (1-7, Q): "

REM Change to test directory
cd /d "%TEST_DIR%"

if "%choice%"=="1" goto quick_test
if "%choice%"=="2" goto entropy_test
if "%choice%"=="3" goto velocity_test
if "%choice%"=="4" goto extension_test
if "%choice%"=="5" goto combined_test
if "%choice%"=="6" goto ui_test
if "%choice%"=="7" goto full_suite
if /i "%choice%"=="q" goto end

goto end

:quick_test
echo.
echo [TEST] Running quick connection test...
echo.
echo To test the connection:
echo   1. Make sure Rakshak is running (npm run tauri dev)
echo   2. Open the Connection Test page in the sidebar
echo   3. Click "Test Connection" button
echo.
echo Expected: Green "BACKEND CONNECTED" indicator
echo.
echo Or run via Tauri:
python -c "import tauri; print('Testing Tauri API...')" 2>nul
echo.
echo [TEST COMPLETE]
goto end

:entropy_test
echo.
echo [TEST] Running entropy spike detection test...
echo.
if not exist "ransomware_simulator.py" (
    echo [ERROR] ransomware_simulator.py not found
    goto end
)
echo Running Python entropy spike simulation...
python ransomware_simulator.py --type entropy --dry-run --count 30
echo.
echo [TEST COMPLETE]
echo.
echo Expected Results:
echo   - Dashboard should show activity
echo   - If entropy detected ^7.5: CRITICAL alert should trigger
echo   - Check the Activity Log and Alerts page
goto end

:velocity_test
echo.
echo [TEST] Running velocity detection test...
echo.
if not exist "ransomware_simulator.py" (
    echo [ERROR] ransomware_simulator.py not found
    goto end
)
echo Running Python velocity attack simulation...
python ransomware_simulator.py --type velocity --dry-run --count 30
echo.
echo [TEST COMPLETE]
echo.
echo Expected Results:
echo   - Dashboard should show rapid file activity
echo   - If velocity exceeds threshold: HIGH alert should trigger
echo   - ProcessMonitor may show elevated scores
goto end

:extension_test
echo.
echo [TEST] Running extension change detection test...
echo.
if not exist "ransomware_simulator.py" (
    echo [ERROR] ransomware_simulator.py not found
    goto end
)
echo Running Python extension change simulation...
python ransomware_simulator.py --type extension --dry-run --count 20
echo.
echo [TEST COMPLETE]
echo.
echo Expected Results:
echo   - Dashboard should show file rename activity
echo   - Extension changes may trigger detection
goto end

:combined_test
echo.
echo [TEST] Running combined multi-vector attack test...
echo.
if not exist "ransomware_simulator.py" (
    echo [ERROR] ransomware_simulator.py not found
    goto end
)
echo Running Python combined attack simulation...
python ransomware_simulator.py --type combined --dry-run --count 30
echo.
echo [TEST COMPLETE]
echo.
echo Expected Results:
echo   - All three attack vectors executed
echo   - Multiple detection triggers possible
echo   - Check Activity Log for all events
goto end

:ui_test
echo.
echo [TEST] UI-Based Threat Simulation
echo.
echo ============================================================
echo HOW TO USE THE CONNECTION TEST PAGE
echo ============================================================
echo.
echo Step 1: Start Rakshak
echo   cd frontend
echo   npm run tauri dev
echo.
echo Step 2: Navigate to Connection Test
echo   - Click "Connection Test" in the sidebar
echo.
echo Step 3: Test Connection
echo   - Click "Test Connection" button
echo   - Should show green "BACKEND CONNECTED"
echo.
echo Step 4: Simulate Threats
echo   - Click "Simulate CRITICAL" to emit critical threat
echo     Expected: Shield turns RED, overlay appears
echo.
echo   - Click "Simulate HIGH" to emit high threat
echo     Expected: Dashboard shows HIGH alert
echo.
echo   - Click "Simulate MEDIUM" to emit medium threat
echo     Expected: Dashboard shows MEDIUM alert
echo.
echo Step 5: Check Results
echo   - Activity Log shows events in real-time
echo   - Alerts page shows threat history
echo.
echo ============================================================
goto end

:full_suite
echo.
echo ============================================================
echo RUNNING FULL TEST SUITE
echo ============================================================
echo.
echo This will test all detection mechanisms.
echo.
echo Step 1: Verify Rakshak is running...
echo   (If not running, press Ctrl+C to abort)
echo   (Continuing in 5 seconds...)
timeout /t 5 /nobreak >nul
echo.
echo Step 2: Testing entropy spike detection...
if exist "ransomware_simulator.py" (
    python ransomware_simulator.py --type entropy --dry-run --count 30
) else (
    echo [SKIP] ransomware_simulator.py not found
)
echo.
echo Step 3: Testing velocity detection...
if exist "ransomware_simulator.py" (
    python ransomware_simulator.py --type velocity --dry-run --count 30
) else (
    echo [SKIP] ransomware_simulator.py not found
)
echo.
echo Step 4: Testing extension change detection...
if exist "ransomware_simulator.py" (
    python ransomware_simulator.py --type extension --dry-run --count 20
) else (
    echo [SKIP] ransomware_simulator.py not found
)
echo.
echo ============================================================
echo FULL SUITE COMPLETE
echo ============================================================
echo.
echo REVIEW YOUR RESULTS:
echo.
echo 1. Check the Dashboard:
echo    - Shield status (Green = safe, Red = threat)
echo    - Activity Log (should show test events)
echo    - System Watcher (may show elevated metrics)
echo.
echo 2. Check the Alerts page:
echo    - Should show threat entries
echo    - Each entry shows process, PID, entropy
echo    - Status should be "Neutralized"
echo.
echo 3. Expected Detection Results:
echo    - Entropy test: May trigger CRITICAL if entropy ^7.5
echo    - Velocity test: May trigger HIGH if rate exceeds threshold
echo    - Extension test: May trigger alerts for extension changes
echo.
echo If no detections occurred, check:
echo    - Rakshak is monitoring the correct directories
echo    - File events are being processed
echo    - Detection thresholds in config
echo.
goto end

:end
echo.
echo ============================================================
echo Test session ended
echo ============================================================
echo.
endlocal
