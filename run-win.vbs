Set fso = CreateObject("Scripting.FileSystemObject")
Set file = fso.OpenTextFile("data\args.txt", 1)
args = ""

Do While Not file.AtEndOfStream
    args = args & file.ReadLine & " "
Loop

file.Close

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """vo_scanner.exe"" " & Trim(args), 0, False
