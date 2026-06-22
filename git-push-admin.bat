@echo off
cd /d "D:\tous\Applications\site web"
echo === Git status ===
git status --short
echo.
echo === Ajout des fichiers ===
git add admin/index.html server.js render.yaml .github/workflows/keepalive.yml
echo.
echo === Commit ===
git commit -m "feat: admin dashboard SPA + nouvelles routes API admin"
echo.
echo === Push vers GitHub ===
git push origin main
echo.
echo === Termine ! ===
pause
