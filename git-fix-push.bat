@echo off
cd /d "D:\tous\Applications\site web"
echo === Commit de tout ce qui reste ===
git add -A
git commit -m "chore: scripts de deploiement" --allow-empty
echo.
echo === Pull avec rebase ===
git pull --rebase origin main
echo.
echo === Push vers GitHub ===
git push origin main
echo.
echo === Termine ! ===
pause
