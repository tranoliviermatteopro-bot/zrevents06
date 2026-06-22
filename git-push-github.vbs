Set oShell = CreateObject("WScript.Shell")

' Ajouter le remote GitHub et pousser le code
oShell.Run "cmd /k ""cd /d ""D:\tous\Applications\site web"" && git remote add origin https://github.com/tranoliviermatteopro-bot/zrevents06.git && git branch -M main && git push -u origin main""", 1, False
