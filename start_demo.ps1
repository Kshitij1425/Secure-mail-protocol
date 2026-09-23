# SecureMailScope Complete Demo Startup
# PowerShell script to start both backend and frontend servers

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SecureMailScope Full Stack Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start backend in new window
Write-Host "Starting Backend Server..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-File", "`"$scriptPath\start_backend.ps1`""

# Wait for backend to initialize
Write-Host "Waiting for backend to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Start frontend in new window
Write-Host "Starting Frontend Server..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-File", "`"$scriptPath\start_frontend.ps1`""

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SecureMailScope is starting..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend:  http://localhost:8000" -ForegroundColor Green
Write-Host "API Docs: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Green
Write-Host ""
Write-Host "Two PowerShell windows opened. Close them to stop the servers." -ForegroundColor Gray
Write-Host "Press any key to exit this launcher..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
