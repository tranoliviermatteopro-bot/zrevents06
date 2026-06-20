Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd /c cd /d ""D:\tous\Applications\site web"" && node get-token.js > token-output.txt 2>&1", 0, True

Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.OpenTextFile("D:\tous\Applications\site web\token-output.txt", 1)
MsgBox f.ReadAll()
f.Close
