Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git add server.js admin && git commit -m ""feat: dashboard admin complet (devis, logs, stats, equipe)"" && git push origin main""", 1, False
