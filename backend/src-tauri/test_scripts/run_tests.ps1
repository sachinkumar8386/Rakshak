# Rakshak Test Suite
# Run this to test the ransomware detection system

Write-Host @"
==========================================================
RAKSHAK RANSOMWARE DETECTION TEST SUITE
==========================================================

Available Tests:
1. Simulate CRITICAL threat (via Tauri)
2. Simulate HIGH threat (via Tauri)
3. Simulate MEDIUM threat (via Tauri)
4. Run entropy spike simulation (Python)
5. Run velocity attack simulation (Python)
6. Run extension change simulation (Python)
7. Run combined attack simulation (Python)
8. Connection test (via Tauri)

==========================================================
"@ -ForegroundColor Cyan

function Get-Selection {
    $selection = Read-Host "Enter test number(s) or 'q' to quit"
    return $selection
}

function Test-Connection {
    Write-Host "`n[TEST] Checking backend connection..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:1420" -TimeoutSec 2 -ErrorAction SilentlyContinue
        Write-Host "[OK] Backend is reachable" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[!] Backend not reachable - is Rakshak running?" -ForegroundColor Red
        return $false
    }
}

function Test-SimulateCritical {
    Write-Host "`n[TEST] Simulating CRITICAL threat..." -ForegroundColor Yellow
    Write-Host "This will emit a CRITICAL level threat event." -ForegroundColor Yellow
    Write-Host "Expected: Shield turns RED, ThreatOverlay appears, Alert sounds." -ForegroundColor Cyan
    # This requires the Tauri app to be running with devtools enabled
    Write-Host "`nTo trigger from the UI: Navigate to 'Connection Test' page and click 'Simulate CRITICAL'" -ForegroundColor Green
}

function Test-EntropySpike {
    Write-Host "`n[TEST] Running entropy spike simulation..." -ForegroundColor Yellow
    Write-Host "This will create files with high-entropy (random) data." -ForegroundColor Yellow
    Write-Host "Expected: Rakshak detects entropy > 7.5 and triggers alert." -ForegroundColor Cyan
    
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $simulatorPath = Join-Path $scriptPath "test_scripts\ransomware_simulator.py"
    
    if (Test-Path $simulatorPath) {
        python $simulatorPath --type entropy --dry-run
    } else {
        Write-Host "[ERROR] Simulator script not found at: $simulatorPath" -ForegroundColor Red
    }
}

function Test-VelocityAttack {
    Write-Host "`n[TEST] Running velocity attack simulation..." -ForegroundColor Yellow
    Write-Host "This will rapidly modify many files in sequence." -ForegroundColor Yellow
    Write-Host "Expected: Rakshak detects high file modification velocity." -ForegroundColor Cyan
    
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $simulatorPath = Join-Path $scriptPath "test_scripts\ransomware_simulator.py"
    
    if (Test-Path $simulatorPath) {
        python $simulatorPath --type velocity --dry-run
    } else {
        Write-Host "[ERROR] Simulator script not found at: $simulatorPath" -ForegroundColor Red
    }
}

function Test-ExtensionChange {
    Write-Host "`n[TEST] Running extension change simulation..." -ForegroundColor Yellow
    Write-Host "This will rename files with suspicious extensions." -ForegroundColor Yellow
    Write-Host "Expected: Rakshak detects extension changes (.txt -> .encrypted)."</ForegroundColor Cyan
    
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $simulatorPath = Join-Path $scriptPath "test_scripts\ransomware_simulator.py"
    
    if (Test-Path $simulatorPath) {
        python $simulatorPath --type extension --dry-run
    } else {
        Write-Host "[ERROR] Simulator script not found at: $simulatorPath" -ForegroundColor Red
    }
}

function Test-CombinedAttack {
    Write-Host "`n[TEST] Running combined multi-vector attack..." -ForegroundColor Yellow
    Write-Host "This will simulate a sophisticated coordinated attack." -ForegroundColor Yellow
    Write-Host "Expected: Multiple detection triggers, combined threat response." -ForegroundColor Cyan
    
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $simulatorPath = Join-Path $scriptPath "test_scripts\ransomware_simulator.py"
    
    if (Test-Path $simulatorPath) {
        python $simulatorPath --type combined --dry-run
    } else {
        Write-Host "[ERROR] Simulator script not found at: $simulatorPath" -ForegroundColor Red
    }
}

function Show-Menu {
    Write-Host @"

TEST MENU
---------
1. Simulate CRITICAL threat (via UI)
2. Simulate HIGH threat (via UI)
3. Simulate MEDIUM threat (via UI)
4. Entropy spike simulation (Python)
5. Velocity attack simulation (Python)
6. Extension change simulation (Python)
7. Combined attack simulation (Python)
8. Test backend connection
9. Run ALL tests (safe mode)
10. Help / Instructions

Enter choice or 'q' to quit: "@ -NoNewline -ForegroundColor Green
}

# Main loop
do {
    Show-Menu
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Test-SimulateCritical }
        "2" { 
            Write-Host "`n[TEST] Simulating HIGH threat..." -ForegroundColor Yellow
            Write-Host "To trigger from the UI: Navigate to 'Connection Test' page and click 'Simulate HIGH'" -ForegroundColor Green
        }
        "3" { 
            Write-Host "`n[TEST] Simulating MEDIUM threat..." -ForegroundColor Yellow
            Write-Host "To trigger from the UI: Navigate to 'Connection Test' page and click 'Simulate MEDIUM'" -ForegroundColor Green
        }
        "4" { Test-EntropySpike }
        "5" { Test-VelocityAttack }
        "6" { Test-ExtensionChange }
        "7" { Test-CombinedAttack }
        "8" { Test-Connection }
        "9" { 
            Write-Host "`n[TEST] Running all tests in safe mode..." -ForegroundColor Yellow
            Test-Connection
            Write-Host "`n--- Running entropy spike test ---" -ForegroundColor Yellow
            Test-EntropySpike
            Write-Host "`n--- Running velocity test ---" -ForegroundColor Yellow
            Test-VelocityAttack
            Write-Host "`n--- Running extension change test ---" -ForegroundColor Yellow
            Test-ExtensionChange
            Write-Host "`n[ALL TESTS COMPLETE]" -ForegroundColor Green
        }
        "10" { 
            Write-Host @"

==========================================================
TESTING INSTRUCTIONS
==========================================================

1. START RAKSHAK
   - Run: cd frontend && npm run tauri dev
   - Wait for the app to fully load

2. OPEN CONNECTION TEST PAGE
   - In the sidebar, click "Connection Test"
   - This page lets you test the backend->frontend connection

3. RUN UI-BASED TESTS
   - Click "Test Connection" to verify backend is responding
   - Click "Simulate CRITICAL" to test critical threat response
   - Click "Simulate HIGH" to test high threat response
   - Click "Simulate MEDIUM" to test medium threat response

4. RUN PYTHON-BASED TESTS
   - These tests create actual file events
   - They trigger the real detection logic in the backend
   - All tests run in DRY-RUN mode by default
   - To run LIVE: python ransomware_simulator.py --type combined --live

5. WHAT TO WATCH FOR
   - Dashboard Shield turns RED during threat
   - Activity Log shows threat events
   - Alerts page shows new threat entries
   - ThreatOverlay appears for critical threats
   - Alert sound plays

6. VERIFY DETECTION
   - Check the Alert History table for entries
   - Each entry shows process, PID, entropy, and reasons
   - Status should show "Neutralized" for blocked threats

==========================================================
"@ -ForegroundColor Cyan
        }
        "q" { break }
        default { Write-Host "[!] Invalid choice" -ForegroundColor Red }
    }
    
    if ($choice -ne "q" -and $choice -ne "10") {
        Write-Host "`nPress Enter to continue..." -NoNewline
        Read-Host
        Clear-Host
    }
} while ($choice -ne "q")

Write-Host "`nExiting test suite. Stay safe!`n" -ForegroundColor Green
