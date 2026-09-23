# SecureMailScope Frontend Startup Script
# PowerShell script to start the React development server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SecureMailScope Frontend Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is available
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: npm not found. Please install Node.js 18+." -ForegroundColor Red
    exit 1
}

# Navigate to frontend directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $scriptPath "frontend")

Write-Host "Installing dependencies (if needed)..." -ForegroundColor Yellow
npm install --silent

Write-Host ""
Write-Host "Starting React dev server on http://localhost:5173..." -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

# Start Vite dev server
npm run dev
