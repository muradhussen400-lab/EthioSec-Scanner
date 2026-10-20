@echo off
echo ========================================================
echo        Starting EthioSec Scanner (Backend & Frontend)
echo ========================================================

echo [1/2] Launching Backend on http://127.0.0.1:8000 ...
start "EthioSec Backend (Port 8000)" cmd /k "cd /d ""%~dp0backend"" && python -m uvicorn main:app --reload --port 8000"

echo [2/2] Launching Frontend on http://127.0.0.1:5500 ...
start "EthioSec Frontend (Port 5500)" cmd /k "cd /d ""%~dp0ETHIOSEC SCANNER 2"" && python -m http.server 5500 --bind 127.0.0.1"

echo.
echo ========================================================
echo Both servers have been launched in separate windows!
echo - Home:         http://127.0.0.1:5500/index.html
echo - Dashboard:    http://127.0.0.1:5500/dashboardfinal.html
echo - New Scan:     http://127.0.0.1:5500/scanfinal.html
echo - Backend Docs: http://127.0.0.1:8000/docs
echo ========================================================
pause
