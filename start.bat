@echo off
echo Starting ShadowMap AI Backend...
start /B cmd /c "cd backend && python app.py"

echo Waiting for backend to initialize...
timeout /t 2 /nobreak > NUL

echo Starting ShadowMap AI Dashboard...
start /B cmd /c "cd dashboard && npm start"

echo Waiting for dashboard to initialize...
timeout /t 5 /nobreak > NUL

echo Starting ShadowMap AI Electron App...
start /B cmd /c "cd electron-app && npm start"

echo ShadowMap AI is running!
pause
