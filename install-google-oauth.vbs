Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && npm install passport passport-google-oauth20""", 1, True
