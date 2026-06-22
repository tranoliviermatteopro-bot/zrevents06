Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git add server.js && git commit -m ""design: embed Discord devis amélioré + boutons valider/refuser"" && git push origin main""", 1, False
