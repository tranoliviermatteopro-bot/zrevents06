Set oShell = CreateObject("WScript.Shell")

' 1. Arrêter le serveur sur le port 3000
oShell.Run "cmd /c for /f ""tokens=5"" %a in ('netstat -ano ^| findstr "":3000 ""') do taskkill /PID %a /F", 0, True
WScript.Sleep 1500

' 2. Activer le compte en base
oShell.Run "cmd /c cd /d ""D:\tous\Applications\site web"" && node activer-compte.js", 0, True
WScript.Sleep 1000

' 3. Relancer le serveur
oShell.Run "cmd /k ""cd /d D:\tous\Applications\site web && node server.js""", 1, False
