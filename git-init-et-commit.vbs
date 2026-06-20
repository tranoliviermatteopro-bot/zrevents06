Set oShell = CreateObject("WScript.Shell")

' 1. Init git + premier commit
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git init && git add . && git commit -m ""Initial commit — zrevents06 boulangerie""" & """", 1, False
