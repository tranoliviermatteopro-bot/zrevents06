Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /c for /f ""tokens=5"" %a in ('netstat -ano ^| findstr "":3001 ""') do taskkill /PID %a /F", 0, True
WScript.Sleep 1000
oShell.Run "cmd /k ""cd /d D:\tous\Applications\site web && node server.js""", 1, False
