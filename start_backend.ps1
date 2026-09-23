# SecureMailScope Backend Startup Script
# PowerShell script to start the FastAPI backend server

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SecureMailScope Backend Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Python not found. Please install Python 3.12+." -ForegroundColor Red
    exit 1
}

# Navigate to backend directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $scriptPath "backend")

Write-Host "Starting FastAPI server on http://localhost:8000..." -ForegroundColor Green
Write-Host "API docs available at http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

# Start uvicorn
python -m uvicorn securemailscope.api.main:app --host 0.0.0.0 --port 8000 --reload
