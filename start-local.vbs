Option Explicit
Dim fileSystem, shell, root, scriptFile, command, quote
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
root = fileSystem.GetParentFolderName(WScript.ScriptFullName)
scriptFile = fileSystem.BuildPath(root, "src\start-web.ps1")
If Not fileSystem.FileExists(scriptFile) Then
  MsgBox "Please extract the complete tool folder before starting.", 16, "Local Tool"
  WScript.Quit 1
End If
quote = Chr(34)
command = quote & shell.ExpandEnvironmentStrings("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe") & quote & " -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File " & quote & scriptFile & quote
On Error Resume Next
shell.Run command, 0, False
If Err.Number <> 0 Then
  MsgBox "Unable to start Windows PowerShell. Please check Windows Script Host is enabled.", 16, "Local Tool"
  WScript.Quit 1
End If
