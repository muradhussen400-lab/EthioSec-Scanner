Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       Starting EthioSec Scanner (Backend & Frontend)   " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Start Backend in a new window
Write-Host "[1/2] Launching Backend on http://127.0.0.1:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\backend'; python -m uvicorn main:app --reload --port 8000"

# 2. Start Frontend in a new window
Write-Host "[2/2] Launching Frontend on http://127.0.0.1:5500 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\ETHIOSEC SCANNER 2'; python -m http.server 5500 --bind 127.0.0.1"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "Both servers are running!" -ForegroundColor Green
Write-Host " - Home:         http://127.0.0.1:5500/index.html" -ForegroundColor White
Write-Host " - Dashboard:    http://127.0.0.1:5500/dashboardfinal.html" -ForegroundColor White
Write-Host " - New Scan:     http://127.0.0.1:5500/scanfinal.html" -ForegroundColor White
Write-Host " - Backend Docs: http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Green
