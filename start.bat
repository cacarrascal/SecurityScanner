@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo.
echo ========================================
echo   SecurityScanner
echo ========================================
echo.

echo [*] Starting Backend (FastAPI on port 8000)...
start "SecurityScanner Backend" cmd /k "cd /d "%ROOT%api" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [*] Starting Frontend (Next.js on port 3000)...
start "SecurityScanner Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo [*] Waiting for services...
echo.

timeout /t 10 /nobreak > nul

echo [*] Opening browser...
start http://localhost:3000

echo.
echo ========================================
echo   Services started:
echo   - Frontend: http://localhost:3000
echo   - Backend:  http://localhost:8000
echo   - API Docs: http://localhost:8000/docs
echo ========================================
echo.
echo Press any key to exit this window...
pause > nul
