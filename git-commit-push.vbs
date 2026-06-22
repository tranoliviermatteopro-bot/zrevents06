Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git add server.js && git commit -m ""Fix CSP : autoriser onclick inline (script-src-attr)"" && git push origin main""", 1, False
