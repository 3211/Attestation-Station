@echo off
echo ============================================
echo  Attestation Station - Lake Boiler Labs
echo ============================================
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH.
    echo Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

echo Node.js found:
node --version
echo.

echo Installing dependencies...
call npm install
if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)
echo.

echo Starting Attestation Station on port 3000...
echo Opening browser...
start "" http://localhost:3000
node server.js