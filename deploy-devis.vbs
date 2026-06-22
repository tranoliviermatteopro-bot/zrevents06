Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git add server.js && git commit -m ""fix: appel /devis bot Discord pour canal devis-en-attente"" && git push origin main""", 1, False
