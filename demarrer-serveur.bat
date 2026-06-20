@echo off
title Serveur zrevents06
echo Fermeture du port 3001...

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3001 "') do (
    taskkill /PID %%a /F >nul 2>&1
)

timeout /t 1 /nobreak >nul
echo Port libere. Demarrage du serveur...
echo.
node server.js
pause
