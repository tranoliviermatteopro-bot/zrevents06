@echo off
cd /d "D:\tous\Applications\site web"
echo === Git pull rebase ===
git pull --rebase origin main
echo.
echo === Push vers GitHub ===
git push origin main
echo.
echo === Termine ! ===
pause
