Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe", 1, false

<script>
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("powershell.exe");
</script>



